/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "src/xenia/kernel/xsocket.h"

#include <cstring>

#include "xenia/base/platform.h"
#include "xenia/kernel/kernel_state.h"
#include "xenia/kernel/xam/xam_module.h"
#include "xenia/kernel/xboxkrnl/xboxkrnl_threading.h"

#include "xenia/kernel/XLiveAPI.h"

using namespace std::chrono_literals;

namespace xe {
namespace kernel {

constexpr bool kLogSocketTraffic = false;

XSocket::XSocket(KernelState* kernel_state)
    : XObject(kernel_state, kObjectType) {}

XSocket::XSocket(KernelState* kernel_state, uint64_t native_handle)
    : XObject(kernel_state, kObjectType), native_handle_(native_handle) {}

XSocket::~XSocket() { Close(); }

X_STATUS XSocket::Initialize(AddressFamily af, Type type, Protocol proto) {
  af_ = af;
  type_ = type;
  proto_ = proto;

  if (proto == Protocol::X_IPPROTO_VDP) {
    // VDP is a layer on top of UDP.
    proto = Protocol::X_IPPROTO_UDP;
  }

  native_handle_ = socket(af, type, proto);
  if (native_handle_ == -1) {
    return X_STATUS_UNSUCCESSFUL;
  }

  if (type_ == X_SOCK_DGRAM || proto_ == X_IPPROTO_UDP ||
      proto_ == X_IPPROTO_VDP) {
    constexpr int kDatagramBufferSize = 4 * 1024 * 1024;

    int receive_buffer_size = kDatagramBufferSize;
    if (setsockopt(native_handle_, SOL_SOCKET, SO_RCVBUF,
                   reinterpret_cast<const char*>(&receive_buffer_size),
                   sizeof(receive_buffer_size)) != 0) {
      XELOGW("XSocket::Initialize: failed to set UDP receive buffer: {}",
             GetLastWSAError());
    }

    int send_buffer_size = kDatagramBufferSize;
    if (setsockopt(native_handle_, SOL_SOCKET, SO_SNDBUF,
                   reinterpret_cast<const char*>(&send_buffer_size),
                   sizeof(send_buffer_size)) != 0) {
      XELOGW("XSocket::Initialize: failed to set UDP send buffer: {}",
             GetLastWSAError());
    }

#ifdef XE_PLATFORM_WIN32
    DWORD udp_connreset = 0;
    DWORD bytes_returned = 0;
    if (WSAIoctl(native_handle_, SIO_UDP_CONNRESET, &udp_connreset,
                 sizeof(udp_connreset), nullptr, 0, &bytes_returned, nullptr,
                 nullptr) != 0) {
      XELOGW("XSocket::Initialize: failed to disable UDP connection reset: {}",
             GetLastWSAError());
    }
#endif
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Close() {
  std::vector<std::future<int>> polling_tasks;
  {
    std::unique_lock lock(receive_mutex_);
    if (native_handle_ == -1) {
      return X_STATUS_SUCCESS;
    }

    for (auto* overlapped : active_overlappeds_) {
      if (overlapped && !(overlapped->offset_high.get() & 1)) {
        overlapped->offset_high = overlapped->offset_high.get() | 2;
      }
    }

    active_overlappeds_.clear();
    polling_tasks = std::move(polling_tasks_);
    receive_cv_.notify_all();
    receive_order_cv_.notify_all();
  }

  for (auto& polling_task : polling_tasks) {
    if (polling_task.valid()) {
      if (polling_task.wait_for(1500ms) == std::future_status::ready) {
        (void)polling_task.get();
      } else {
        XELOGW("XSocket::Close: receive worker did not stop before close");
      }
    }
  }

  std::unique_lock socket_lock(receive_socket_mutex_);
  const auto native_handle = native_handle_;
  native_handle_ = -1;
#if XE_PLATFORM_WIN32
  int ret = closesocket(native_handle);
#elif XE_PLATFORM_LINUX
  int ret = close(native_handle);
#endif
  socket_lock.unlock();

  if (ret != 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::GetOption(uint32_t level, uint32_t optname, void* optval_ptr,
                            uint32_t* optlen) {
  int ret =
      getsockopt(native_handle_, level, optname, static_cast<char*>(optval_ptr),
                 reinterpret_cast<socklen_t*>(optlen));

  // Because values provided in optval_ptr are in LE we must to somehow save
  // them in BE.
  switch (*optlen) {
    case 1:
      xe::copy_and_swap<uint8_t>((uint8_t*)optval_ptr, (uint8_t*)optval_ptr, 1);
      break;
    case 4:
      xe::copy_and_swap<uint32_t>((uint32_t*)optval_ptr, (uint32_t*)optval_ptr,
                                  1);
      break;
    case 8:
      xe::copy_and_swap<uint64_t>((uint64_t*)optval_ptr, (uint64_t*)optval_ptr,
                                  1);
      break;
    default:
      XELOGE("XSocket::GetOption - Unhandled optlen: {}", *optlen);
      break;
  }

  if (ret < 0) {
    // TODO: WSAGetLastError()
    return X_STATUS_UNSUCCESSFUL;
  }
  return X_STATUS_SUCCESS;
}
X_STATUS XSocket::SetOption(uint32_t level, uint32_t optname, void* optval_ptr,
                            uint32_t optlen) {
  if (level == 0xFFFF && (optname == 0x5801 || optname == 0x5802)) {
    // Disable socket encryption
    secure_ = false;
    return X_STATUS_SUCCESS;
  }

  void* proper_ptr =
      GetOptValueWithProperEndianness(optval_ptr, optname, optlen);

  int ret = setsockopt(native_handle_, level, optname, (const char*)proper_ptr,
                       optlen);

  // Cheezy way to check if we created some additional allocation.
  if (optval_ptr != proper_ptr) {
    free(proper_ptr);
  }

  if (ret < 0) {
    // TODO: WSAGetLastError()
    return X_STATUS_UNSUCCESSFUL;
  }

  // SO_BROADCAST
  if (level == 0xFFFF && optname == 0x0020) {
    broadcast_socket_ = true;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::IOControl(uint32_t cmd, uint8_t* arg_ptr) {
#ifdef XE_PLATFORM_WIN32
  const bool is_nonblocking_request = cmd == FIONBIO && arg_ptr;
  const bool requested_nonblocking =
      is_nonblocking_request && *reinterpret_cast<u_long*>(arg_ptr) != 0;
  int ret = ioctlsocket(native_handle_, cmd, (u_long*)arg_ptr);
  if (ret < 0) {
    // TODO: Get last error
    return X_STATUS_UNSUCCESSFUL;
  }
  if (is_nonblocking_request) {
    nonblocking_ = requested_nonblocking;
  }

  return X_STATUS_SUCCESS;
#elif XE_PLATFORM_LINUX
  return X_STATUS_UNSUCCESSFUL;
#endif
}

X_STATUS XSocket::Connect(const XSOCKADDR_IN* name, int name_len) {
  XSOCKADDR_IN sa_in = XSOCKADDR_IN();
  memcpy(&sa_in, name, sizeof(XSOCKADDR_IN));

  sa_in.address_port =
      XLiveAPI::upnp_handler->GetMappedConnectPort(name->address_port);

  sockaddr addr = sa_in.to_host();

  int ret = connect(native_handle_, &addr, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Bind(const XSOCKADDR_IN* name, int name_len) {
  XSOCKADDR_IN sa_in = XSOCKADDR_IN();
  memcpy(&sa_in, name, sizeof(XSOCKADDR_IN));

  sa_in.address_port =
      XLiveAPI::upnp_handler->GetMappedBindPort(name->address_port);

  sockaddr addr = sa_in.to_host();

  int ret = bind(native_handle_, &addr, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  bound_port_ = sa_in.address_port;

  if (!bound_port_) {
    XSOCKADDR_IN sa = *name;

    if (!GetSockName(&sa, &name_len)) {
      bound_port_ = sa.address_port;
    }
  }

  bound_ = true;

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Listen(int backlog) {
  int ret = listen(native_handle_, backlog);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

object_ref<XSocket> XSocket::Accept(XSOCKADDR_IN* name, int* name_len) {
  sockaddr sa = {};
  int addrlen = 0;
  const bool is_name_and_name_len_available = name && name_len;

  if (is_name_and_name_len_available) {
    addrlen = byte_swap(*name_len);
  }

  const uint64_t ret = accept(native_handle_, name ? &sa : nullptr,
                              name_len ? &addrlen : nullptr);
  if (ret == -1) {
    return nullptr;
  }

  if (is_name_and_name_len_available) {
    name->to_guest(&sa);
    *name_len = byte_swap(addrlen);
  }
  // Create a kernel object to represent the new socket, and copy parameters
  // over.
  auto socket = object_ref<XSocket>(new XSocket(kernel_state_, ret));
  socket->af_ = af_;
  socket->type_ = type_;
  socket->proto_ = proto_;

  return socket;
}

int XSocket::Shutdown(int how) { return shutdown(native_handle_, how); }

int XSocket::Recv(uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return recv(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags);
}

int XSocket::RecvFrom(uint8_t* buf, uint32_t buf_len, uint32_t flags,
                      XSOCKADDR_IN* from, uint32_t* from_len) {
  sockaddr sa{};
  int host_from_len = from_len ? static_cast<int>(*from_len) : 0;

  if (from) {
    sa = from->to_host();
  }

  int ret = recvfrom(native_handle_, reinterpret_cast<char*>(buf), buf_len,
                     flags, from ? &sa : nullptr,
                     from_len ? &host_from_len : nullptr);

  if (from) {
    from->to_guest(&sa);
  }
  if (from_len) {
    *from_len = static_cast<uint32_t>(host_from_len);
  }

  return ret;
}

struct WSARecvFromData {
  XWSABUF* buffers;
  uint32_t num_buffers;
  uint32_t flags;
  XSOCKADDR_IN* from;
  xe::be<uint32_t>* from_len;
  XWSAOVERLAPPED* overlapped;
  uint64_t sequence = 0;
  bool ordered = false;
};

int XSocket::PollWSARecvFrom(bool wait, WSARecvFromData receive_async_data) {
  receive_async_data.overlapped->internal_high = 0;

  struct pollfd fds[1];
  fds->fd = native_handle_;
  fds->events = POLLIN;

  DWORD bytes_received = 0;
  DWORD flags = receive_async_data.flags;
  auto buffers = new WSABUF[receive_async_data.num_buffers];

  int ret;
  if (wait && receive_async_data.ordered) {
    std::unique_lock lock(receive_mutex_);
    receive_order_cv_.wait(lock, [&]() {
      return (receive_async_data.overlapped->offset_high.get() & 2) ||
             receive_async_data.sequence == receive_dequeue_sequence_;
    });

    if (receive_async_data.overlapped->offset_high.get() & 2) {
      receive_async_data.overlapped->internal_high =
          static_cast<uint32_t>(X_WSAError::X_WSA_OPERATION_ABORTED);
      ret = -1;
      goto threadexit;
    }
  }

retry_poll:
  do {
#ifdef XE_PLATFORM_WIN32
    ret = WSAPoll(fds, 1, wait ? 1000 : 0);
#else
    ret = poll(fds, 1, wait ? 1000 : 0);
#endif

    if (receive_async_data.overlapped->offset_high & 2) {
      receive_async_data.overlapped->internal_high =
          (uint32_t)X_WSAError::X_WSA_OPERATION_ABORTED;
      ret = -1;
      goto threadexit;
    }
  } while (ret == 0 && wait);

  if (ret < 0) {
    receive_async_data.overlapped->internal_high = WSAGetLastError();
    XELOGE("XSocket receive thread failed polling with error {}",
           static_cast<uint32_t>(receive_async_data.overlapped->internal_high));
    goto threadexit;
  } else if (ret == 0) {
    receive_async_data.overlapped->internal_high =
        (uint32_t)X_WSAError::X_WSAEWOULDBLOCK;
    ret = -1;
    goto threadexit;
  }

#ifdef XE_PLATFORM_WIN32
  for (auto i = 0u; i < receive_async_data.num_buffers; i++) {
    buffers[i].len = receive_async_data.buffers[i].len;
    buffers[i].buf =
        reinterpret_cast<CHAR*>(kernel_state()->memory()->TranslateVirtual(
            receive_async_data.buffers[i].buf_ptr));
  }

  {
    std::unique_lock socket_lock(receive_socket_mutex_);

    sockaddr addr = {};
    sockaddr* sa = nullptr;
    int from_len = 0;
    if (receive_async_data.from) {
      addr = receive_async_data.from->to_host();
      sa = &addr;
      from_len = receive_async_data.from_len
                     ? static_cast<int>(receive_async_data.from_len->get())
                     : sizeof(sockaddr);
    }

    uint32_t receive_error = 0;
    if (native_handle_ == -1) {
      ret = -1;
      receive_error = static_cast<uint32_t>(X_WSAError::X_WSAENOTSOCK);
    } else {
      bool temporary_nonblocking = false;
      if (!nonblocking_) {
        u_long enable_nonblocking = 1;
        temporary_nonblocking =
            ioctlsocket(native_handle_, FIONBIO, &enable_nonblocking) == 0;
      }
      ret = ::WSARecvFrom(native_handle_, buffers,
                          receive_async_data.num_buffers, &bytes_received,
                          &flags, sa,
                          receive_async_data.from ? &from_len : nullptr,
                          nullptr, nullptr);
      if (ret < 0) {
        receive_error = GetLastWSAError();
      }
      if (temporary_nonblocking) {
        u_long disable_nonblocking = 0;
        ioctlsocket(native_handle_, FIONBIO, &disable_nonblocking);
      }
    }
    if (ret < 0) {
      if (wait &&
          receive_error ==
              static_cast<uint32_t>(X_WSAError::X_WSAEWOULDBLOCK)) {
        socket_lock.unlock();
        goto retry_poll;
      }
      receive_async_data.overlapped->internal_high = receive_error;
    } else {
      receive_async_data.overlapped->internal = bytes_received;
    }
    if (ret >= 0 && receive_async_data.from) {
      auto* sin = reinterpret_cast<sockaddr_in*>(&addr);
      if (kLogSocketTraffic) {
        XELOGI("XSocket::PollWSARecvFrom: async received {} bytes from "
               "{}.{}.{}.{}:{}",
               bytes_received, sin->sin_addr.S_un.S_un_b.s_b1,
               sin->sin_addr.S_un.S_un_b.s_b2,
               sin->sin_addr.S_un.S_un_b.s_b3,
               sin->sin_addr.S_un.S_un_b.s_b4, ntohs(sin->sin_port));
      }
      receive_async_data.from->to_guest(&addr);
      if (receive_async_data.from_len) {
        *receive_async_data.from_len = static_cast<uint32_t>(from_len);
      }
    }
    socket_lock.unlock();
  }

  receive_async_data.overlapped->offset = flags;
#else
  auto buffers = new iovec[receive_async_data.num_buffers];
  for (auto i = 0u; i < receive_async_data.num_buffers; i++) {
    buffers[i].iov_len = receive_async_data.buffers[i].len;
    buffers[i].iov_base = kernel_state()->memory()->TranslateVirtual(
        receive_async_data.buffers[i].buf_ptr);
  }

  msghdr msg;
  std::memset(&msg, 0, sizeof(msg));
  msg.msg_name = &n_from;
  msg.msg_namelen = n_from_len;
  msg.msg_iov = buffers;
  msg.msg_iovlen = receive_async_data.num_buffers;

  {
    std::unique_lock socket_lock(receive_socket_mutex_);
    ret = recvmsg(native_handle_, &msg, receive_async_data.flags);
    if (ret < 0) {
      receive_async_data.overlapped->internal_high = GetLastWSAError();
    } else {
      receive_async_data.overlapped->internal = ret;
    }
    socket_lock.unlock();
  }

  flags = 0;
  if (msg.msg_flags & MSG_TRUNC) flags |= MSG_PARTIAL;
  if (msg.msg_flags & MSG_OOB) flags |= MSG_OOB;
  receive_async_data.overlapped->offset = flags;

  if (ret >= 0) {
    SetLastWSAError((X_WSAError)0);
    ret = 0;
  }
#endif

threadexit:
  delete[] buffers;

  std::unique_lock lock(receive_mutex_);
  if (wait) {
    delete[] receive_async_data.buffers;
  }

  receive_async_data.overlapped->offset_high =
      receive_async_data.overlapped->offset_high.get() | 1;

  if (wait && receive_async_data.ordered &&
      receive_async_data.sequence == receive_dequeue_sequence_) {
    receive_dequeue_sequence_++;
    receive_order_cv_.notify_all();
  }

  if (receive_async_data.overlapped->event_handle) {
    xboxkrnl::xeNtSetEvent(receive_async_data.overlapped->event_handle,
                           nullptr);
  }

  receive_cv_.notify_all();
  lock.unlock();

  return ret;
}

int XSocket::WSARecvFrom(XWSABUF* buffers, uint32_t num_buffers,
                         xe::be<uint32_t>* num_bytes_recv_ptr,
                         xe::be<uint32_t>* flags_ptr, XSOCKADDR_IN* from_ptr,
                         xe::be<uint32_t>* fromlen_ptr,
                         XWSAOVERLAPPED* overlapped_ptr) {
  if (!buffers || !flags_ptr || (from_ptr && !fromlen_ptr)) {
    SetLastWSAError(X_WSAError::X_WSA_INVALID_PARAMETER);
    return -1;
  }

  // On win32 we could pipe all this directly to WSARecvFrom.
  // We would however need find a way to call the completion callback without
  // relying on the caller to set the "alertable" flag to true when waiting. We
  // also need to do our own async handling anyway for Linux so we might as well
  // make the code paths the same to improve symmetry in behaviour.

  WSARecvFromData receive_async_data;
  receive_async_data.buffers = buffers;
  receive_async_data.num_buffers = num_buffers;
  receive_async_data.flags = *flags_ptr;
  receive_async_data.from = from_ptr;
  receive_async_data.from_len = fromlen_ptr;

  XWSAOVERLAPPED tmp_overlapped;
  std::memset(&tmp_overlapped, 0, sizeof(tmp_overlapped));
  receive_async_data.overlapped =
      overlapped_ptr ? overlapped_ptr : &tmp_overlapped;

  bool defer_receive = false;
  if (overlapped_ptr) {
    std::unique_lock lock(receive_mutex_);
    for (auto it = polling_tasks_.begin(); it != polling_tasks_.end();) {
      if (it->valid() && it->wait_for(0ms) == std::future_status::ready) {
        (void)it->get();
        it = polling_tasks_.erase(it);
      } else {
        ++it;
      }
    }

    for (auto it = active_overlappeds_.begin();
         it != active_overlappeds_.end();) {
      auto* active_overlapped = *it;
      if (!active_overlapped || active_overlapped->offset_high.get() & 1) {
        it = active_overlappeds_.erase(it);
      } else if (active_overlapped == overlapped_ptr) {
        SetLastWSAError(X_WSAError::X_WSA_IO_PENDING);
        return -1;
      } else {
        defer_receive = true;
        ++it;
      }
    }
  }

  int ret = -1;
  if (defer_receive) {
    receive_async_data.overlapped->internal_high =
        static_cast<uint32_t>(X_WSAError::X_WSAEWOULDBLOCK);
  } else {
    ret = PollWSARecvFrom(false, receive_async_data);
  }

  if (ret < 0) {
    auto wsa_error = receive_async_data.overlapped->internal_high.get();
    SetLastWSAError((X_WSAError)wsa_error);

    if (overlapped_ptr && wsa_error == (uint32_t)X_WSAError::X_WSAEWOULDBLOCK) {
      receive_mutex_.lock();

      for (auto it = polling_tasks_.begin(); it != polling_tasks_.end();) {
        if (it->valid() &&
            it->wait_for(0ms) == std::future_status::ready) {
          (void)it->get();
          it = polling_tasks_.erase(it);
        } else {
          ++it;
        }
      }

      for (auto it = active_overlappeds_.begin();
           it != active_overlappeds_.end();) {
        auto* active_overlapped = *it;
        if (!active_overlapped || active_overlapped->offset_high.get() & 1) {
          it = active_overlappeds_.erase(it);
        } else {
          ++it;
        }
      }

      // These may have been on the stack - copy them.
      receive_async_data.buffers = new XWSABUF[num_buffers];
      std::memcpy(receive_async_data.buffers, buffers,
                  num_buffers * sizeof(XWSABUF));
      receive_async_data.sequence = receive_enqueue_sequence_++;
      receive_async_data.ordered = true;

      overlapped_ptr->offset_high = 0;
      if (overlapped_ptr->event_handle) {
        xboxkrnl::xeNtClearEvent(overlapped_ptr->event_handle);
      }
      active_overlappeds_.push_back(overlapped_ptr);
      polling_tasks_.push_back(
          std::async(std::launch::async, &XSocket::PollWSARecvFrom, this, true,
                     receive_async_data));
      SetLastWSAError(X_WSAError::X_WSA_IO_PENDING);

      receive_mutex_.unlock();
    }
  } else {
    if (num_bytes_recv_ptr) {
      *num_bytes_recv_ptr = receive_async_data.overlapped->internal;
    }
    *flags_ptr = receive_async_data.overlapped->offset;
  }

  return ret;
}

bool XSocket::WSAGetOverlappedResult(XWSAOVERLAPPED* overlapped_ptr,
                                     xe::be<uint32_t>* bytes_transferred,
                                     bool wait, xe::be<uint32_t>* flags_ptr) {
  if (!overlapped_ptr || !bytes_transferred || !flags_ptr) {
    SetLastWSAError(X_WSAError::X_WSA_INVALID_PARAMETER);
    return false;
  }

  std::unique_lock lock(receive_mutex_);
  if (!(overlapped_ptr->offset_high.get() & 1)) {
    if (wait) {
      receive_cv_.wait(lock, [&]() {
        return (overlapped_ptr->offset_high.get() & 1) != 0;
      });
    } else {
      SetLastWSAError(X_WSAError::X_WSA_IO_INCOMPLETE);
      return false;
    }
  }

  if (overlapped_ptr->internal_high != 0) {
    SetLastWSAError((X_WSAError)overlapped_ptr->internal_high.get());
    for (auto it = active_overlappeds_.begin();
         it != active_overlappeds_.end();) {
      if (*it == overlapped_ptr) {
        it = active_overlappeds_.erase(it);
      } else {
        ++it;
      }
    }
    return false;
  }

  *bytes_transferred = overlapped_ptr->internal;
  *flags_ptr = overlapped_ptr->offset;

  for (auto it = active_overlappeds_.begin();
       it != active_overlappeds_.end();) {
    if (*it == overlapped_ptr) {
      it = active_overlappeds_.erase(it);
    } else {
      ++it;
    }
  }

  return true;
}

int XSocket::Send(const uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return send(native_handle_, reinterpret_cast<const char*>(buf), buf_len,
              flags);
}

int XSocket::SendTo(uint8_t* buf, uint32_t buf_len, uint32_t flags,
                    XSOCKADDR_IN* to, uint32_t to_len) {
  XSOCKADDR_IN sa_in = XSOCKADDR_IN();
  sockaddr addr = {};
  sockaddr* addr_ptr = nullptr;
  if (to) {
    sa_in = *to;
    sa_in.address_port =
        XLiveAPI::upnp_handler->GetMappedConnectPort(sa_in.address_port);
    addr = sa_in.to_host();
    addr_ptr = &addr;
  }

  return sendto(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                addr_ptr, to_len);
}

int XSocket::WSAEventSelect(uint64_t socket_handle, uint64_t event_handle,
                            uint32_t flags) {
  return ::WSAEventSelect(socket_handle, reinterpret_cast<HANDLE>(event_handle),
                          flags);
}

bool XSocket::QueuePacket(uint32_t src_ip, uint16_t src_port,
                          const uint8_t* buf, size_t len) {
  packet* pkt = reinterpret_cast<packet*>(new uint8_t[sizeof(packet) + len]);
  pkt->src_ip = src_ip;
  pkt->src_port = src_port;

  pkt->data_len = (uint16_t)len;
  std::memcpy(pkt->data, buf, len);

  std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
  incoming_packets_.push((uint8_t*)pkt);

  // TODO: Limit on number of incoming packets?
  return true;
}

X_STATUS XSocket::GetPeerName(XSOCKADDR_IN* buf, int* buf_len) {
  sockaddr addr = buf->to_host();
  sockaddr* sa = const_cast<sockaddr*>(&addr);

  int ret = getpeername(native_handle_, sa, (socklen_t*)buf_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  buf->to_guest(sa);
  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::GetSockName(XSOCKADDR_IN* buf, int* buf_len) {
  sockaddr addr = buf->to_host();
  sockaddr* sa = const_cast<sockaddr*>(&addr);

  int ret = getsockname(native_handle_, sa, (socklen_t*)buf_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  buf->to_guest(sa);
  return X_STATUS_SUCCESS;
}

uint32_t XSocket::GetLastWSAError() const {
  // Todo(Gliniak): Provide error mapping table
  // Xbox error codes might not match with what we receive from OS
#ifdef XE_PLATFORM_WIN32
  return WSAGetLastError();
#endif
  return errno;
}

void XSocket::SetLastWSAError(X_WSAError error) const {
#ifdef XE_PLATFORM_WIN32
  WSASetLastError((int)error);
#endif
  errno = (int)error;
}

}  // namespace kernel
}  // namespace xe

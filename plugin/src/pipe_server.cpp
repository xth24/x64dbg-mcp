#include "pipe_server.h"

#include "pipe_protocol.h"

#include <stdexcept>

PipeServer::PipeServer(std::wstring pipe_name, Handler handler)
    : pipe_name_(std::move(pipe_name)), handler_(std::move(handler)) {}

PipeServer::~PipeServer() {
    stop();
}

bool PipeServer::start() {
    if (running_.exchange(true)) {
        return true;
    }
    try {
        worker_ = std::thread([this] { run(); });
        return true;
    } catch (...) {
        running_ = false;
        return false;
    }
}

void PipeServer::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    poke();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void PipeServer::run() {
    while (running_) {
        HANDLE pipe = CreateNamedPipeW(
            pipe_name_.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            1024 * 1024,
            1024 * 1024,
            0,
            nullptr);

        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(250);
            continue;
        }

        const BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected && running_) {
            handle_client(pipe);
        }

        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
}

void PipeServer::handle_client(HANDLE pipe) {
    try {
        write_json_frame(pipe, handler_(read_json_frame(pipe)));
    } catch (const std::exception& exc) {
        try {
            write_json_frame(pipe, {
                {"ok", false},
                {"error", {{"code", "bridge_error"}, {"message", exc.what()}}},
            });
        } catch (...) {
        }
    }
}

void PipeServer::poke() {
    HANDLE handle = CreateFileW(
        pipe_name_.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
}

#pragma once

#include <Windows.h>
#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <nlohmann/json.hpp>

class PipeServer {
public:
    using Handler = std::function<nlohmann::json(const nlohmann::json&)>;

    PipeServer(std::wstring pipe_name, Handler handler);
    ~PipeServer();

    bool start();
    void stop();

private:
    void run();
    void handle_client(HANDLE pipe);
    void poke();

    std::wstring pipe_name_;
    Handler handler_;
    std::atomic_bool running_{false};
    std::thread worker_;
};

#pragma once

#include <filesystem>
#include <string>

class SessionFile {
public:
    bool create();
    void remove();

    const std::wstring& pipe_name() const { return pipe_name_; }
    const std::string& session_id() const { return session_id_; }

private:
    std::filesystem::path session_dir() const;

    std::string session_id_;
    std::wstring pipe_name_;
    std::filesystem::path path_;
};

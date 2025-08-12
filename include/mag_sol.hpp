#pragma once

#include <iostream>
#include <variant>
#include <unordered_map>
#include <vector>
#include <functional>
#include <memory>
#include <future>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <stdexcept>
#include <string>
#include <chrono>
#include <sqlite3.h>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace MagSolSettings {

class Config {
public:
    Config() : enable_logging(false), db_path("mag_sol_logs.db"), log_level(LogLevel::INFO) {}

    enum class LogLevel {
        DEBUG = 0,
        INFO = 1,
        WARN = 2,
        ERROR = 3,
    };

    bool enable_logging;
    std::string db_path;
    LogLevel log_level;

    // setters
    Config& setLogging(bool enabled) { enable_logging = enabled; return *this; };
    Config& setDbPath(const std::string& path) { db_path = path; return *this; };
    Config& setLogLevel(LogLevel level) { log_level = level; return *this; };
    };

} // namespace MagSolSettings

namespace MagSol {

struct Func {
    std::function<void(void*)> call_fn; // function that takes an actor pointer

    // constructor
    template<typename F>
    Func(F&& f) : call_fn(std::forward<F>(f)) {}
};

using InstructionPayload = std::variant<std::string, Func>;

class Message {
public:
    Message(int s_id, InstructionPayload s_instruct) 
        : sender_id(s_id), instruction(s_instruct) {}

    template<typename T>
    static Message makeFuncPayload(int sender_id, void (T::*method)()) {
        auto func = [method](void* actor_ptr) {
            std::invoke(method, static_cast<T*>(actor_ptr));
        };
        return Message(sender_id, Func(std::move(func)));
    }

    template<typename F>
    static Message makeFuncPayload(int sender_id, F&& func) {
        return Message(sender_id, Func(std::forward<F>(func)));
    }

    static Message makeCustomPayload(int sender_id, const std::string& custom) {
        return Message(sender_id, custom);
    }

    int sender_id;
    InstructionPayload instruction;
    std::shared_ptr<std::promise<void>> completion_promise;
};

class Logger {
public:
    Logger(const MagSolSettings::Config& config) : config_(config), db_(nullptr) {
        if (config.enable_logging) {
            initializeDatabase();
        }
    }

    ~Logger() {
        if (db_) {
            sqlite3_close(db_);
        }
    }

    void logActorSpawn(int actor_id, const std::string& actor_type) {
        if (!config_.enable_logging || config_.log_level > MagSolSettings::Config::LogLevel::INFO) 
            return;

        logEvent("ACTOR_SPAWN", actor_id, -1, "Actor spawned: type= " + actor_type + ", id= " + std::to_string(actor_id));
    }

    void logActorDestroy(int actor_id) {
        if (!config_.enable_logging || config_.log_level > MagSolSettings::Config::LogLevel::INFO) 
            return;

        logEvent("ACTOR_DESTROY", actor_id, -1, "Actor destroyed: id= " + std::to_string(actor_id));
    }

    void logMessageSent(int sender_id, int receiver_id, const std::string& message_type) {
        if (!config_.enable_logging || config_.log_level > MagSolSettings::Config::LogLevel::DEBUG) 
            return;

        logEvent("MESSAGE_SENT", receiver_id, sender_id, "Message sent: type= " + message_type);
    }

    void logMessageProcessed(int actor_id, int sender_id, const std::string& message_type, 
                            double processing_time_ms) {
        if (!config_.enable_logging || config_.log_level > MagSolSettings::Config::LogLevel::DEBUG) 
            return;
            
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(3);
        oss << "Message processed: type=" << message_type 
            << ", processing_time=" << processing_time_ms << "ms";
        
        logEvent("MESSAGE_PROCESSED", actor_id, sender_id, oss.str());
    }

    void logError(int actor_id, const std::string& error_message) {
        if (!config_.enable_logging) return;
        
        logEvent("ERROR", actor_id, -1, "Error: " + error_message);
    }
    
    void logWarning(int actor_id, const std::string& warning_message) {
        if (!config_.enable_logging || config_.log_level > MagSolSettings::Config::LogLevel::WARN) 
            return;
            
        logEvent("WARNING", actor_id, -1, "Warning: " + warning_message);
    }
    
    void logCustom(int actor_id, const std::string& event_type, const std::string& details) {
        if (!config_.enable_logging || config_.log_level > MagSolSettings::Config::LogLevel::INFO) 
            return;
            
        logEvent(event_type, actor_id, -1, details);
    }

private:
    void initializeDatabase() {
        int rc = sqlite3_open(config_.db_path.c_str(), &db_);
        if (rc != SQLITE_OK) {
            std::cerr << "Cannot open Database: " << sqlite3_errmsg(db_) << std::endl;
            db_ = nullptr;
            return;
        }

        const char* create_table_sql = R"(
            CREATE TABLE IF NOT EXISTS mag_sol_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor_id INTEGER,
                sender_id INTEGER,
                details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_timestamp ON mag_sol_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_actor ON mag_sol_logs(actor_id);
            CREATE INDEX IF NOT EXISTS idx_event_type ON mag_sol_logs(event_type);
        )";

        char* error_msg = nullptr;
        rc = sqlite3_exec(db_, create_table_sql, nullptr, nullptr, &error_msg);
        if (rc != SQLITE_OK) {
            std::cerr << "SQL ERROR: " << error_msg << std::endl;
            sqlite3_free(error_msg);
        }
    }

    void logEvent(const std::string& event_type, int actor_id, int sender_id, const std::string& details) {
        if (!db_) return;

        std::lock_guard<std::mutex> lock(db_mutex_);

        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()) % 1000;

        // Use thread-safe gmtime_r on Unix/Linux or gmtime_s on Windows
        std::tm tm_utc{};
        if (
        #ifdef _WIN32
            gmtime_s(&tm_utc, &time_t_now) != 0
        #else
            gmtime_r(&time_t_now, &tm_utc) == nullptr
        #endif
        ) {
            std::cerr << "Failed to convert time\n";
            return;
        }

        std::ostringstream timestamp_ss;
        timestamp_ss << std::put_time(&tm_utc, "%Y-%m-%d %H:%M:%S");
        timestamp_ss << '.' << std::setfill('0') << std::setw(3) << ms.count();

        const char* insert_sql = R"(
            INSERT INTO mag_sol_logs (timestamp, event_type, actor_id, sender_id, details)
            VALUES (?, ?, ?, ?, ?);
        )";
        
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db_, insert_sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
            return;
        }

        sqlite3_bind_text(stmt, 1, timestamp_ss.str().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, event_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, actor_id);
        if (sender_id >= 0) {
            sqlite3_bind_int(stmt, 4, sender_id);
        } else {
            sqlite3_bind_null(stmt, 4);
        }
        sqlite3_bind_text(stmt, 5, details.c_str(), -1, SQLITE_TRANSIENT);
        
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
        }
        
        sqlite3_finalize(stmt);
    }

    MagSolSettings::Config config_;
    sqlite3* db_;
    std::mutex db_mutex_;
};

class Actor {
public:
    virtual ~Actor() = default;
    virtual void processMessage(const Message& msg) = 0;

    void setLogger(std::shared_ptr<Logger> logger) {
        logger_ = logger;
    }

    std::queue<Message> message_queue;
    std::mutex queue_mutex;
    std::condition_variable cv;
    std::atomic<bool> running{false};
    std::future<void> worker_future;
    int actor_id = -1;

    void messageLoop() {
        while (running) {
            std::unique_lock<std::mutex> lock(queue_mutex);
            cv.wait(lock, [this]() { return !message_queue.empty() || !running; });

            while (!message_queue.empty() && running) {
                Message msg = message_queue.front();
                message_queue.pop();
                lock.unlock();

                auto start_time = std::chrono::high_resolution_clock::now();

                try {
                    processMessage(msg);

                    auto end_time = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
                    double processing_time_ms = duration.count() / 1000.0;

                    if (logger_) {
                        std::string msg_type = std::holds_alternative<std::string>(msg.instruction) ? "STRING" : "FUNCTION";
                        logger_->logMessageProcessed(actor_id, msg.sender_id, msg_type, processing_time_ms);
                    }
                } catch (const std::exception& e) {
                    if (logger_) {
                        logger_->logError(actor_id, "Exception in processMessage: " + std::string(e.what()));
                    }
                }
                    
                if (msg.completion_promise) {
                    msg.completion_promise->set_value();
                }

                lock.lock();
            }
        }
    }

    void receive(const Message& msg) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        message_queue.push(msg);
        cv.notify_one();
    }

protected:
    std::shared_ptr<Logger> logger_;
};

class ActorHandleBase {
public:
    virtual ~ActorHandleBase() = default;
    virtual void receive(const Message& msg) = 0;
};

template <class T>
class ActorHandle : public ActorHandleBase {
public:
    ActorHandle(std::shared_ptr<T> actor) : actor_ptr(actor) {}

    void receive(const Message& msg) override {
        actor_ptr.get()->receive(msg);
    }

private:
    std::shared_ptr<T> actor_ptr;
};

class Engine {
public:
    Engine(MagSolSettings::Config u_config) : config_(u_config) {
        if (config_.enable_logging) {
            logger_ = std::make_shared<Logger>(config_);
        }
    }

    template<typename T>
    int spawnActor() {
        static_assert(std::is_base_of_v<Actor, T>, "T must inherit from Actor");
        
        int id = next_id;
        next_id++;

        auto actor = std::make_shared<T>();
        actor->running = true;
        actor->actor_id = id;

        if (logger_) {
            actor->setLogger(logger_);
            logger_->logActorSpawn(id, typeid(T).name());
        }

        actor->worker_future = std::async(std::launch::async, [actor]() {
            actor->messageLoop();
        });

        auto handle = std::make_unique<ActorHandle<T>>(actor);

        actors[id] = actor;
        handles[id] = std::move(handle);

        return id;
    }

    std::future<void> sendMessage(int id, const std::vector<Message>& messages) {
        auto it = handles.find(id);
        if (it != handles.end()) {
            auto promise = std::make_shared<std::promise<void>>();
            auto future = promise->get_future();

            // Log message sending
            if (logger_) {
                for (const auto& msg : messages) {
                    std::string msg_type = std::holds_alternative<std::string>(msg.instruction) ? 
                        "STRING" : "FUNCTION";
                    logger_->logMessageSent(msg.sender_id, id, msg_type);
                }
            }

            // wait for every message
            for (int i = 0; i < messages.size(); i++) {
                Message msg = messages[i];
                if (i == messages.size() - 1) {
                    msg.completion_promise = promise; // last 1
                }
                handles[id]->receive(msg);
            }
            return future;
        } else {
            auto promise = std::make_shared<std::promise<void>>();
            auto future = promise->get_future();
            promise->set_exception(std::make_exception_ptr(std::runtime_error("Actor not found")));
            
            if (logger_) {
                logger_->logError(-1, "Attempted to send message to non-existent actor: " + std::to_string(id));
            }
            
            return future;
        }
    }

    void destroyActor(int id) {
        if (auto it = handles.find(id); it != handles.end()) {
            auto& actor = actors[id];
            actor->running = false;
            actor->cv.notify_all();

            if (actor->worker_future.valid()) {
                actor->worker_future.wait();
            }

            if (logger_) {
                logger_->logActorDestroy(id);
            }

            actors.erase(id);
            handles.erase(id);
        }
    }

private:
    std::unordered_map<int, std::shared_ptr<Actor>> actors;
    std::unordered_map<int, std::unique_ptr<ActorHandleBase>> handles;
    int next_id = 1;
    MagSolSettings::Config config_;
    std::shared_ptr<Logger> logger_;
};

} // namespace MagSol

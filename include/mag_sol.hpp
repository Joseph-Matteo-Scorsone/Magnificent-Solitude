#pragma once

#include <variant>
#include <unordered_map>
#include <vector>
#include <functional>
#include <iostream>
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

namespace ActorModel {

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
        auto func = Func([method](void* actor_ptr) {
            auto* typed_actor = static_cast<T*>(actor_ptr);
            (typed_actor->*method)();
        });
        return Message(sender_id, std::move(func));
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

class Actor {
public:
    virtual ~Actor() = default;
    virtual void processMessage(const Message& msg) = 0;

    std::queue<Message> message_queue;
    std::mutex queue_mutex;
    std::condition_variable cv;
    std::atomic<bool> running{false};
    std::future<void> worker_future;

    void messageLoop() {
        while (running) {
            std::unique_lock<std::mutex> lock(queue_mutex);
            cv.wait(lock, [this]() { return !message_queue.empty() || !running; });

            while (!message_queue.empty() && running) {
                Message msg = message_queue.front();
                message_queue.pop();
                lock.unlock();

                processMessage(msg);

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
    Engine() = default;

    template<typename T>
    int spawnActor() {
        static_assert(std::is_base_of_v<Actor, T>, "T must inherit from Actor");
        
        int id = next_id;
        next_id++;

        auto actor = std::make_shared<T>();
        actor->running = true;

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
            return future;
        }
    }

    void poisonActor(int id) {
        if (auto it = handles.find(id); it != handles.end()) {
            auto& actor = actors[id];
            actor->running = false;
            actor->cv.notify_all();

            if (actor->worker_future.valid()) {
                actor->worker_future.wait();
            }

            actors.erase(id);
            handles.erase(id);
        }
    }

private:
    std::unordered_map<int, std::shared_ptr<Actor>> actors;
    std::unordered_map<int, std::unique_ptr<ActorHandleBase>> handles;
    int next_id = 1;
};

} // namespace ActorModel
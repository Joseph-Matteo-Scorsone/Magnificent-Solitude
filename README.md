# MagSol - Actor Model Framework for C++

A lightweight, header-only actor model framework for C++ with built-in logging and database persistence capabilities.

## Features

- **Header-only library** - Easy integration with `#include "mag_sol.hpp"`
- **Actor-based concurrency** - Implements the actor model pattern for safe concurrent programming
- **Asynchronous messaging** - Send string messages or function calls to actors
- **SQLite logging** - Optional comprehensive logging of actor lifecycle and message processing
- **Thread-safe** - Built-in synchronization for actor message queues
- **Configurable** - Flexible configuration system for logging levels and database paths

## Quick Start

### Basic Example

```cpp
#include "mag_sol.hpp"
#include <iostream>

class Counter : public MagSol::Actor {
public:
    int counter = 0;

    void processMessage(const MagSol::Message& msg) override {
        if (auto* custom = std::get_if<std::string>(&msg.instruction)) {
            if (*custom == "increment") {
                counter++;
                std::cout << "Counter: " << counter << std::endl;
            }
        }
    }
};

int main() {
    // Configure the engine
    auto config = MagSolSettings::Config()
        .setLogging(true)
        .setLogLevel(MagSolSettings::Config::LogLevel::INFO);
    
    MagSol::Engine engine(config);
    
    // Spawn an actor
    int counter_id = engine.spawnActor<Counter>();
    
    // Send messages
    std::vector<MagSol::Message> messages = {
        MagSol::Message::makeCustomPayload(0, "increment")
    };
    
    auto future = engine.sendMessage(counter_id, messages);
    future.get(); // Wait for completion
    
    engine.destroyActor(counter_id);
    return 0;
}
```

## Building

### Requirements

- C++17 compatible compiler
- CMake 3.10 or higher
- SQLite3 (included as static dependency)

### Build Instructions

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## Configuration

### Logging Configuration

```cpp
auto config = MagSolSettings::Config()
    .setLogging(true)                                    // Enable/disable logging
    .setDbPath("custom_logs.db")                        // SQLite database path
    .setLogLevel(MagSolSettings::Config::LogLevel::DEBUG); // Set log level
```

### Log Levels

- `DEBUG` - All events including message processing times
- `INFO` - Actor lifecycle and general events
- `WARN` - Warning messages only
- `ERROR` - Error messages only

## API Reference

### Core Classes

#### `MagSol::Actor`
Base class for all actors. Override `processMessage()` to handle incoming messages.

#### `MagSol::Engine`
Main engine for managing actors and message routing.

#### `MagSol::Message`
Represents messages that can contain either string payloads or function calls.

### Key Methods

- `Engine::spawnActor<T>()` - Create and start a new actor instance
- `Engine::sendMessage(id, messages)` - Send messages to an actor
- `Engine::destroyActor(id)` - Stop and cleanup an actor
- `Message::makeCustomPayload(sender_id, string)` - Create string message
- `Message::makeFuncPayload(sender_id, function)` - Create function message

## Logging Features

When enabled, MagSol automatically logs:

- Actor spawn/destroy events
- Message sending and processing
- Processing time metrics
- Error and warning events
- Custom user events

Logs are stored in SQLite database with indexing for efficient querying.

## Thread Safety

- Each actor runs in its own thread with a message queue
- All message passing is thread-safe
- Database logging operations are protected by mutexes
- Actor lifecycle operations are safe for concurrent access

## License

See LICENSE file for details.
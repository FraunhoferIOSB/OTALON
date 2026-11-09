#pragma once
#include <condition_variable>
#include <exception>
#include <mutex>
#include <queue>

/**
 * @brief Thread save wrapper around std::queue.
 *
 * Creates a thread save wrapper around the std::queue with thread save
 * accessor functions for the queue.
 *
 * @tparam T Datatype of the queue.
 */
template<typename T>
class ThreadSaveQueue
{
  protected:
    std::queue<T> buffer;
    std::mutex mu;
    std::condition_variable cv;
    bool is_stopped{ false };

  public:
    /**
     * @brief Push data to the queue.
     *
     * Wait for the mutex to lock the access to the queue.
     * Pushes data entry to the queue.
     *
     * @param data Data to push to the queue.
     */
    void push(T const& data)
    {
        std::unique_lock<std::mutex> lk(mu);
        bool was_empty = buffer.empty();
        buffer.push(data);

        lk.unlock();

        if (was_empty) {
            cv.notify_one();
        }
    }

    /**
     * @brief Pop data from the queue.
     *
     * Wait for the mutex to lock the access to the queue.
     * Pop data from the queue. If no data is available in the queue
     * waits for new data.
     *
     * @throws std::exception If queue is stopped and empty.
     *
     * @return Data from the queue.
     */
    T wait_and_pop()
    {
        std::unique_lock<std::mutex> lk(mu);

        while (!is_stopped && buffer.empty()) {
            cv.wait(lk);
        }
        if (is_stopped && buffer.empty()) {
            throw std::exception();
        }

        auto ret = buffer.front();
        buffer.pop();

        lk.unlock();
        return ret;
    }

    void stop()
    {
        is_stopped = true;
        cv.notify_all();
    }
};

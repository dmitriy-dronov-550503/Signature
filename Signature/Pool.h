#pragma once
#include <queue>
#include <mutex>
#include <boost/interprocess/sync/named_semaphore.hpp>

template<typename T>
class Pool
{
private:
    std::queue<std::shared_ptr<T>> items;
    std::mutex poolMutex;

public:

    std::shared_ptr<T> allocate() {
        std::shared_ptr<T> item;
        poolMutex.lock();
        if (!items.empty())
        {
            item = items.front();
            items.pop();
        }
        poolMutex.unlock();
        return item;
    }

    void release(std::shared_ptr<T> item) {
        poolMutex.lock();
        items.push(item);
        poolMutex.unlock();
    }
};

template<typename T>
class SyncPool
{
private:
    std::queue<std::shared_ptr<T>> items;
    std::mutex poolMutex;
    std::string sName;
    unsigned int itemsCount;
    unsigned int maxItems;
    bool isInit = false;

public:

    ~SyncPool() {
        boost::interprocess::named_semaphore::remove(sName.c_str());
    }

    void init(std::string semaphoreName, unsigned int initialCount) {
        sName = semaphoreName;
        itemsCount = 0;
        maxItems = initialCount;
        boost::interprocess::named_semaphore::remove(sName.c_str());
        boost::interprocess::named_semaphore semaphore(boost::interprocess::create_only_t(), sName.c_str(), initialCount);
        for (unsigned int i = 0; i < initialCount; i++) {
            semaphore.wait(); // Lock allocation before pool initialization with actual data
        }
        isInit = true;
    }

    std::shared_ptr<T> allocate() {
        assert(isInit);
        boost::interprocess::named_semaphore semaphore(boost::interprocess::open_only_t(), sName.c_str());
        semaphore.wait();
        std::shared_ptr<T> item;
        {
            std::lock_guard<std::mutex> lock(poolMutex);
            if (!items.empty())
            {
                item = items.front();
                items.pop();
            }
            itemsCount--;
        }
        return item;
    }

    void release(std::shared_ptr<T> item) {
        assert(isInit);
        boost::interprocess::named_semaphore semaphore(boost::interprocess::open_only_t(), sName.c_str());
        {
            std::lock_guard<std::mutex> lock(poolMutex);
            itemsCount++;
            if (itemsCount > maxItems) throw std::exception("Pool overwhelmed with number of items that can be controlled by semaphore");
            items.push(item);
        }
        semaphore.post();
    }
};
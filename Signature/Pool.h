#pragma once
#include <queue>
#include <mutex>
#include <boost/interprocess/sync/named_semaphore.hpp>

// Pool class allows to create a pool of objects that can be allocated
// and released when needed. It is thread safe. It does not have
// objects quantity limitation. Objects must be created with 
// std::make_shared and added to the pool via Release method.
template<typename T>
class Pool
{
private:
    std::queue<std::shared_ptr<T>> items;
    std::mutex poolMutex;

public:

    std::shared_ptr<T> Allocate() {
        std::shared_ptr<T> item;
        std::lock_guard<std::mutex> lock(poolMutex);
        if (!items.empty())
        {
            item = items.front();
            items.pop();
        }
        return item;
    }

    void Release(std::shared_ptr<T> item) {
        std::lock_guard<std::mutex> lock(poolMutex);
        items.push(item);
    }
};

// SyncPool class allows to create a pool of objects that can be allocated
// and released when needed. Allocate operation is blocking and waits until
// an object is available. It is thread safe. Quantity of objects must
// be defined. Objects must be created with std::make_shared and added to
// the pool via Release method.
template<typename T>
class SyncPool
{
private:
    std::queue<std::shared_ptr<T>> items;
    std::mutex poolMutex;
    std::string sName;
    unsigned int itemsCount = 0;
    unsigned int maxItems = 0;
    bool isInit = false;

public:

    ~SyncPool() {
        boost::interprocess::named_semaphore::remove(sName.c_str());
    }

    void Init(std::string semaphoreName, unsigned int initialCount) {
        assert(semaphoreName != "");
        assert(initialCount > 0);
        sName = semaphoreName;
        itemsCount = 0;
        maxItems = initialCount;
        boost::interprocess::named_semaphore::remove(sName.c_str());
        boost::interprocess::named_semaphore semaphore(boost::interprocess::create_only_t(), sName.c_str(), initialCount);
        for (unsigned int i = 0; i < initialCount; i++) {
            semaphore.wait(); // Lock allocation while pool is empty
        }
        isInit = true;
    }

    std::shared_ptr<T> Allocate() {
        assert(isInit);
        boost::interprocess::named_semaphore semaphore(boost::interprocess::open_only_t(), sName.c_str());
        semaphore.wait();
        std::shared_ptr<T> item;
        std::lock_guard<std::mutex> lock(poolMutex);
        if (!items.empty())
        {
            item = items.front();
            items.pop();
        }
        itemsCount--;
        return item;
    }

    void Release(std::shared_ptr<T> item) {
        assert(isInit);
        boost::interprocess::named_semaphore semaphore(boost::interprocess::open_only_t(), sName.c_str());
        std::lock_guard<std::mutex> lock(poolMutex);
        itemsCount++;
        if (itemsCount > maxItems) throw std::runtime_error("SyncPool class exception. Pool is overwhelmed with number of items that can be controlled by semaphore");
        items.push(item);
        semaphore.post();
    }

    const unsigned int GetMaxItems() {
        return maxItems;
    }
};
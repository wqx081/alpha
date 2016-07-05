#ifndef BASE_SEMAPHORE_H_
#define BASE_SEMAPHORE_H_

#include "base/lazy_instance.h"
#include <semaphore.h>  // NOLINT

namespace base {

// Forward declarations.
class TimeDelta;

// ----------------------------------------------------------------------------
// Semaphore
//
// A semaphore object is a synchronization object that maintains a count. The
// count is decremented each time a thread completes a wait for the semaphore
// object and incremented each time a thread signals the semaphore. When the
// count reaches zero,  threads waiting for the semaphore blocks until the
// count becomes non-zero.

class Semaphore final {
 public:
  explicit Semaphore(int count);
  ~Semaphore();

  // Increments the semaphore counter.
  void Signal();

  // Suspends the calling thread until the semaphore counter is non zero
  // and then decrements the semaphore counter.
  void Wait();

  // Suspends the calling thread until the counter is non zero or the timeout
  // time has passed. If timeout happens the return value is false and the
  // counter is unchanged. Otherwise the semaphore counter is decremented and
  // true is returned.
  bool WaitFor(const TimeDelta& rel_time) ;

  typedef sem_t NativeHandle;

  NativeHandle& native_handle() {
    return native_handle_;
  }
  const NativeHandle& native_handle() const {
    return native_handle_;
  }

 private:
  NativeHandle native_handle_;

  DISALLOW_COPY_AND_ASSIGN(Semaphore);
};


// POD Semaphore initialized lazily (i.e. the first time Pointer() is called).
// Usage:
//   // The following semaphore starts at 0.
//   static LazySemaphore<0>::type my_semaphore = LAZY_SEMAPHORE_INITIALIZER;
//
//   void my_function() {
//     // Do something with my_semaphore.Pointer().
//   }
//

template <int N>
struct CreateSemaphoreTrait {
  static Semaphore* Create() {
    return new Semaphore(N);
  }
};

template <int N>
struct LazySemaphore {
  typedef typename LazyDynamicInstance<Semaphore, CreateSemaphoreTrait<N>,
                                       ThreadSafeInitOnceTrait>::type type;
};

#define LAZY_SEMAPHORE_INITIALIZER LAZY_DYNAMIC_INSTANCE_INITIALIZER

}  // namespace base
#endif  // V8_BASE_PLATFORM_SEMAPHORE_H_

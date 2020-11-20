#ifndef __CICFLOWMETER_UTIL_ATOMIC_H__
#define __CICFLOWMETER_UTIL_ATOMIC_H__

#include <stdatomic.h>

#define ATOMIC_DECLARE(type, name) _Atomic(type) name##__atomic__

/**
 *  \brief wrapper for referencing an atomic variable declared on another file.
 *
 *  \param type Type of the variable (char, short, int, long, long long)
 *  \param name Name of the variable.
 *
 *  We just declare the variable here as we rely on atomic operations
 *  to modify it, so no need for locks.
 *
 */
#define ATOMIC_EXTERN(type, name) extern _Atomic(type)(name##__atomic__)

/**
 *  \brief wrapper for declaring an atomic variable and initializing it.
 **/
#define ATOMIC_DECL_AND_INIT(type, name) _Atomic(type)(name##__atomic__) = 0

/**
 *  \brief wrapper for initializing an atomic variable.
 **/
#define ATOMIC_INIT(name) (name##__atomic__) = 0
#define ATOMIC_INITPTR(name) (name##__atomic__) = NULL

/**
 *  \brief wrapper for reinitializing an atomic variable.
 **/
#define ATOMIC_RESET(name) ATOMIC_INIT(name)

/**
 *  \brief add a value to our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to add to the variable
 */
#define ATOMIC_ADD(name, val) atomic_fetch_add(&(name##__atomic__), (val))

/**
 *  \brief sub a value from our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to sub from the variable
 */
#define ATOMIC_SUB(name, val) atomic_fetch_sub(&(name##__atomic__), (val))

/**
 *  \brief Bitwise OR a value to our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to OR to the variable
 */
#define ATOMIC_OR(name, val) atomic_fetch_or(&(name##__atomic__), (val))

/**
 *  \brief Bitwise AND a value to our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to AND to the variable
 */
#define ATOMIC_AND(name, val) atomic_fetch_and(&(name##__atomic__), (val))

/**
 *  \brief atomic Compare and Switch
 *
 *  \warning "name" is passed to us as "&var"
 */
#define ATOMIC_CAS(name, cmpval, newval) \
    atomic_compare_exchange_strong((name##__atomic__), &(cmpval), (newval))

/**
 *  \brief Get the value from the atomic variable.
 *
 *  \retval var value
 */
#define ATOMIC_GET(name) atomic_load(&(name##__atomic__))

/**
 *  \brief Set the value for the atomic variable.
 *
 *  \retval var value
 */
#define ATOMIC_SET(name, val) atomic_store(&(name##__atomic__), (val))

#endif

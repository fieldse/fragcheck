// Package collect gathers host facts: the running and installed kernel
// versions, distribution, loaded/built-in/blacklisted modules, and relevant
// sysctls. It is the impure layer — it shells out to dpkg/rpm/uname and reads
// /proc — and provides the real version comparator used by the detector.
package collect

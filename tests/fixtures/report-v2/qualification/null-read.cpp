// Controlled Windows x64 qualification fixture; never run on production data.
// CANARY_VARIANT=2 builds a deliberately different PDB identity.
#ifndef CANARY_VARIANT
#define CANARY_VARIANT 1
#endif
volatile int* g_bad = nullptr;
__declspec(noinline) int ReadNull(volatile int* address) {
#if CANARY_VARIANT == 2
  volatile int mismatch_marker = 2;
  if (mismatch_marker == 0) return 0;
#endif
  return *address;  // Expected fixture fault: a read through a null pointer.
}
__declspec(noinline) int CanaryEntry() { return ReadNull(g_bad); }
int main() { return CanaryEntry(); }

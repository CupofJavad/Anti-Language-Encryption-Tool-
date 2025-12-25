# Solution #3: Fix kyber_decapsulate Function Call

## Problem
Decryption may fail when PQ (post-quantum) ciphertext is present due to incorrect function signature.

## Root Cause
`kyber_decapsulate` expects `(ct: bytes, sk: bytes)` but code was calling with `(ident.x_priv, pq_ct)` which is wrong order and wrong type.

## Solution Applied
1. Extract private key bytes using `raw_priv_bytes_x`
2. Call `kyber_decapsulate(pq_ct, x_priv_bytes)` with correct parameters
3. Added proper error handling

## Files Modified
- `web_app/app.py` - Fixed kyber_decapsulate call in decrypt function

## Status
✅ Applied - Decryption should work correctly with PQ ciphertext

## Code Change
```python
# Before (incorrect):
pq_ss = kyber_decapsulate(ident.x_priv, pq_ct)

# After (correct):
x_priv_bytes = raw_priv_bytes_x(ident.x_priv)
pq_ss = kyber_decapsulate(pq_ct, x_priv_bytes)
```


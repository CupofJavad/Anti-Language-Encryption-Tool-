#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rank lexicons in ./lexicons by how well they match a ciphertext's token "shape":
- length histogram distance (L1)
- character trigram cosine similarity
- composite score = 0.6 * L1_length + 0.4 * (1 - cosine_trigram)

Usage:
  python tools/lexicon_fit.py path/to/ciphertext.txt \
      --lexdir ./lexicons --minlen 2 --maxlen 20 --top 10
"""

import argparse, os, math, unicodedata, glob, io
from collections import Counter, defaultdict

def is_letter(ch: str) -> bool:
    return unicodedata.category(ch).startswith("L")

def tokenize_letters_only(txt: str, minlen=2, maxlen=10**9):
    out, cur = [], []
    for ch in txt:
        if is_letter(ch):
            cur.append(ch.lower())
        else:
            if cur:
                w = "".join(cur)
                if minlen <= len(w) <= maxlen:
                    out.append(w)
                cur = []
    if cur:
        w = "".join(cur).lower()
        if minlen <= len(w) <= maxlen:
            out.append(w)
    return out

def trigram_counts(words):
    c = Counter()
    for w in words:
        s = f"^{w}$"  # boundary markers to capture edges
        for i in range(len(s) - 2):
            c[s[i:i+3]] += 1
    return c

def cosine_sim(c1: Counter, c2: Counter):
    if not c1 or not c2:
        return 0.0
    keys = set(c1) | set(c2)
    dot = sum(c1[k]*c2[k] for k in keys)
    n1 = math.sqrt(sum(v*v for v in c1.values()))
    n2 = math.sqrt(sum(v*v for v in c2.values()))
    if n1 == 0 or n2 == 0:
        return 0.0
    return dot / (n1*n2)

def length_hist(words, lo=2, hi=20):
    hist = Counter()
    for w in words:
        L = max(lo, min(len(w), hi))
        hist[L] += 1
    tot = sum(hist.values()) or 1
    # normalize to probabilities
    return {L: hist[L]/tot for L in range(lo, hi+1)}

def l1_distance(h1, h2):
    # both dicts have same support (or we ensure it)
    keys = set(h1) | set(h2)
    return sum(abs(h1.get(k,0.0)-h2.get(k,0.0)) for k in keys)

def read_file(path):
    with io.open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def read_wordlist(path, minlen=2, maxlen=20):
    words = []
    with io.open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip().lower()
            if not w:
                continue
            if not all(is_letter(ch) for ch in w):
                continue
            if minlen <= len(w) <= maxlen:
                words.append(w)
    return words

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ciphertext", help="path to themed text to analyze")
    ap.add_argument("--lexdir", default="./lexicons", help="directory containing lexicon .txt files")
    ap.add_argument("--minlen", type=int, default=2)
    ap.add_argument("--maxlen", type=int, default=20)
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()

    txt = read_file(args.ciphertext)
    cipher_words = tokenize_letters_only(txt, args.minlen, args.maxlen)
    if not cipher_words:
        print("No tokens found in ciphertext (check file/encoding).")
        return

    c_len = length_hist(cipher_words, args.minlen, args.maxlen)
    c_tri = trigram_counts(cipher_words)

    rows = []
    for path in sorted(glob.glob(os.path.join(args.lexdir, "*.txt"))):
        code = os.path.splitext(os.path.basename(path))[0]
        words = read_wordlist(path, args.minlen, args.maxlen)
        if len(words) < 50:
            continue
        l_len = length_hist(words, args.minlen, args.maxlen)
        l_tri = trigram_counts(words)

        d_len = l1_distance(c_len, l_len)               # 0 (best) .. 2 (worst)
        sim_tri = cosine_sim(c_tri, l_tri)              # 1 (best) .. 0 (worst)
        composite = 0.6 * d_len + 0.4 * (1.0 - sim_tri)

        rows.append((composite, d_len, 1.0-sim_tri, code, len(words), path))

    if not rows:
        print("No lexicon files found or all too small.")
        return

    rows.sort(key=lambda r: r[0])  # lower composite is better
    print(f"{'rank':>4}  {'code':<18}  {'words':>6}  {'lenL1':>7}  {'1-cosTri':>9}  {'score':>8}")
    print("-"*60)
    for i, (comp, dlen, one_minus_cos, code, n, path) in enumerate(rows[:args.top], 1):
        print(f"{i:>4}  {code:<18}  {n:>6}  {dlen:7.4f}  {one_minus_cos:9.4f}  {comp:8.4f}")
    print("\nBest guess theme key:", rows[0][3])

if __name__ == "__main__":
    main()
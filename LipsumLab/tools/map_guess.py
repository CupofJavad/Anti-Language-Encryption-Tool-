#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Guess a mapping (theme→source) and decode a themed text without the original map.

Workflow:
1) Tokenize ciphertext into words (letters only) and separators (punct/space).
2) Build a first-pass inverse map by length-bucketed frequency → frequency,
   preferring short, high-frequency function words for short tokens.
3) Optimize by swapping mapped pairs to improve a simple language score:
   score = unigram_logprob + dictionary_hits - vowelless_penalty - weird_char_runs.
4) Save decoded draft + guessed map JSON.

Usage:
  python tools/map_guess.py ciphertext.txt fl_custom_full --src en --lexdir ./lexicons \
      --iters 15000 --seed 1337
"""

import argparse, os, io, json, time, random, math, unicodedata
from collections import Counter, defaultdict, OrderedDict
from datetime import datetime

# --- Utilities ---------------------------------------------------------------

def is_letter(ch: str) -> bool:
    return unicodedata.category(ch).startswith("L")

def tokenize_mixed(txt: str):
    """
    Return a list of (is_word, text) preserving punctuation/spacing.
    Words are sequences of letters; everything else is separators.
    """
    out, cur, in_word = [], [], False
    for ch in txt:
        letter = is_letter(ch)
        if letter:
            if not in_word:
                if cur:
                    out.append((False, "".join(cur)))
                    cur = []
                in_word = True
            cur.append(ch)
        else:
            if in_word:
                out.append((True, "".join(cur)))
                cur = []
                in_word = False
            cur.append(ch)
    if cur:
        out.append((True, "".join(cur)) if in_word else (False, "".join(cur)))
    return out

def lower_letters_only(w: str):
    return "".join(ch.lower() for ch in w if is_letter(ch))

def words_from_stream(stream):
    return [lower_letters_only(t) for isw, t in stream if isw and len(lower_letters_only(t)) >= 2]

def restore_case(src_word: str, dst_word: str):
    # preserve Title/UPPER/case-insensitive forms for cosmetics
    if src_word.isupper():
        return dst_word.upper()
    if src_word[0].isupper():
        return dst_word[:1].upper() + dst_word[1:]
    return dst_word

# --- Lightweight English resources ------------------------------------------

# A compact, ordered list of common English words (freq ≈ decreasing).
# You can replace/extend this with a larger list or load from lexicons/en.txt.
EN_BASE = """
the of and to in is it that for on as with was are be by at from this have or not but you his her they we an he she which their one all more been if when who will would can there what so about up out into than other could time only new some over after also our may first people any like then no my your just now did because how most me them back way even down work use long make go see year those very day where through before good world still same last great while say own under take found such right get place end both since much off few part want high set between another within small every home during big without open put next large number give man again systems state group life hand point house water city face head kind line side case light night yes etc
""".split()

# Tiny stopword anchors for short tokens (len<=3). Ordered by desirability.
EN_SHORT2 = ["to","of","in","is","it","we","he","as","at","by","or","an","be","if","my"]
EN_SHORT3 = ["the","and","for","are","not","you","but","all","can","any","her","was","one","has","out","new"]

EN_SET = set(EN_BASE)

def word_unigram_logprob(word: str):
    # crude logprob using rank: earlier words get higher score
    try:
        idx = EN_BASE.index(word)
        # convert rank to pseudo-prob
        return -math.log(1.0 + idx)
    except ValueError:
        # small penalty for OOVs
        return -8.0

def text_score_wordlist(decoded_words):
    if not decoded_words:
        return -1e9
    n = len(decoded_words)
    hits = sum(1 for w in decoded_words if w in EN_SET)
    vowelless = sum(1 for w in decoded_words if not any(v in w for v in "aeiouy"))
    avg_uni = sum(word_unigram_logprob(w) for w in decoded_words) / n
    score = (hits / n) * 3.0 + avg_uni - 1.0 * (vowelless / n)
    return score

# --- Mapping machinery -------------------------------------------------------

def bucket_len(L):
    if L <= 3: return "b_short"
    if 4 <= L <= 6: return "b4_6"
    if 7 <= L <= 10: return "b7_10"
    if 11 <= L <= 14: return "b11_14"
    return "b_long"

def build_target_vocab(src_lang: str, lexdir: str):
    """
    Build target vocabulary by length and priority.
    Strategy:
      1) Try lexicons/<src_lang>.txt if present (content words).
      2) Always include EN_BASE (function words) if src_lang == 'en'.
    """
    vocab = defaultdict(list)
    path = os.path.join(lexdir, f"{src_lang}.txt")
    seen = set()

    def add_word(w, boost=False):
        wl = lower_letters_only(w)
        if not wl or wl in seen:
            return
        seen.add(wl)
        vocab[len(wl)].append((wl, 2 if boost else 1))

    # from lexicon file (if exists)
    if os.path.exists(path):
        with io.open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if w:
                    add_word(w, boost=False)

    # augment with base English (common function words)
    if src_lang == "en":
        for w in EN_BASE:
            add_word(w, boost=True)

    # sort each length bucket by boost first then alphabet
    for L, lst in vocab.items():
        lst.sort(key=lambda t: (-t[1], t[0]))
        vocab[L] = [w for (w, _) in lst]
    return vocab

def build_initial_map(cipher_types_by_len, target_vocab_by_len):
    """
    Greedy length-bucketed frequency→frequency assignment.
    Lock anchors for short tokens (<=3).
    Returns theme2source dict.
    """
    t2s = {}
    used_targets = set()

    # Lock short anchors where possible
    for L, anchor_list in [(2, EN_SHORT2), (3, EN_SHORT3)]:
        if L not in cipher_types_by_len:
            continue
        cands = cipher_types_by_len[L]  # list of (theme_token, freq)
        for i, (ctok, _) in enumerate(cands):
            if i >= len(anchor_list):
                break
            tgt = anchor_list[i]
            if len(tgt) != L:  # length mismatch guard
                continue
            if tgt in used_targets:
                continue
            t2s[ctok] = tgt
            used_targets.add(tgt)

    # Fill remaining by length-bucket greedily
    for L, cands in cipher_types_by_len.items():
        tv = list(target_vocab_by_len.get(L, []))
        # Skip ones already used
        tv = [w for w in tv if w not in used_targets]
        j = 0
        for ctok, _freq in cands:
            if ctok in t2s:
                continue
            # find next unused target (prefer exact length)
            tgt = None
            while j < len(tv):
                candidate = tv[j]; j += 1
                if candidate not in used_targets:
                    tgt = candidate; break
            if tgt is None:
                # length relax: try nearby lengths ±1
                for d in (1, -1, 2, -2):
                    tv2 = target_vocab_by_len.get(L+d, [])
                    for candidate in tv2:
                        if candidate not in used_targets:
                            tgt = candidate; break
                    if tgt: break
            if tgt is None:
                # fallback: fabricate a pronounceable-ish stub
                tgt = fabricate_stub(L)
                # ensure uniqueness
                k = 1
                while tgt in used_targets:
                    tgt = tgt + "x"
                    k += 1
            t2s[ctok] = tgt
            used_targets.add(tgt)

    return t2s

def fabricate_stub(L):
    # very simple syllable-ish maker; you can replace with your corpus-based generator
    syll = ["an","in","on","al","ar","or","en","es","ti","ra","li","ver","con","pre","pro","de","re","tion","ment","est","ing"]
    out = ""
    while len(out) < L:
        out += random.choice(syll)
    return out[:L]

def decode_stream(stream, map_theme_to_source):
    out = []
    for isw, text in stream:
        if not isw:
            out.append(text)
        else:
            src = text
            key = lower_letters_only(src)
            mapped = map_theme_to_source.get(key, key)
            out.append(restore_case(src, mapped))
    return "".join(out)

def invert_map(d):
    return {v:k for k,v in d.items()}

# --- Optimizer ---------------------------------------------------------------

def optimize_map(stream, theme2source, iters=15000, seed=1337):
    random.seed(seed)
    # build inventory of themewords we actually see
    types = list({lower_letters_only(t) for isw, t in stream if isw and len(lower_letters_only(t))>=2})
    # precompute positions of words to speed up rescoring
    positions = []
    for i,(isw,t) in enumerate(stream):
        if isw:
            positions.append(i)

    def current_score_of_map(m):
        decoded_words = [lower_letters_only(m.get(lower_letters_only(stream[i][1]), lower_letters_only(stream[i][1])))
                         for i in positions]
        return text_score_wordlist(decoded_words)

    best_map = dict(theme2source)
    best_score = current_score_of_map(best_map)
    current_map = dict(best_map)
    current_score = best_score

    # candidate list for swaps (stick to similar lengths)
    by_len = defaultdict(list)
    for w in types:
        by_len[len(w)].append(w)

    def try_swap(a, b, m):
        m[a], m[b] = m[b], m[a]

    # annealing params
    T0, T_end = 1.0, 0.01
    for step in range(1, iters+1):
        # pick a length bucket that exists
        L = random.choice(list(by_len.keys()))
        bucket = by_len[L]
        if len(bucket) < 2:
            continue
        a, b = random.sample(bucket, 2)
        # don't swap if identical mapping
        if current_map.get(a) == current_map.get(b):
            continue

        old_a, old_b = current_map[a], current_map[b]
        try_swap(a, b, current_map)
        new_score = current_score_of_map(current_map)

        # annealed acceptance
        frac = step / iters
        T = max(T_end, T0 * (1.0 - frac))
        accept = (new_score >= current_score) or (random.random() < math.exp((new_score-current_score)/max(1e-6,T)))
        if accept:
            current_score = new_score
            if new_score > best_score:
                best_score, best_map = new_score, dict(current_map)
        else:
            # revert
            current_map[a], current_map[b] = old_a, old_b

        if step % max(500, iters//20) == 0:
            print(f"[{step}/{iters}] score={current_score:.4f} best={best_score:.4f}")

    return best_map, best_score

# --- Main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ciphertext", help="path to themed text")
    ap.add_argument("theme_key", help="theme key for logging (e.g., latin, fl_custom_full)")
    ap.add_argument("--src", default="en", help="assumed source language (default: en)")
    ap.add_argument("--lexdir", default="./lexicons", help="lexicons directory (for src vocab)")
    ap.add_argument("--iters", type=int, default=15000, help="optimizer iterations")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    # read ciphertext
    with io.open(args.ciphertext, "r", encoding="utf-8", errors="ignore") as f:
        txt = f.read()

    stream = tokenize_mixed(txt)
    words = words_from_stream(stream)
    if not words:
        print("No tokens found in ciphertext; aborting.")
        return

    # build target vocab (source language)
    tgt_vocab_by_len = build_target_vocab(args.src, args.lexdir)

    # group theme types by length, sorted by frequency
    freq = Counter(words)
    types = list(freq.keys())
    by_len = defaultdict(list)
    for w in types:
        by_len[len(w)].append((w, freq[w]))
    for L in by_len:
        by_len[L].sort(key=lambda p: (-p[1], p[0]))

    # initial map (theme->source)
    theme2source = build_initial_map(by_len, tgt_vocab_by_len)

    print(f"Initial map size: {len(theme2source)} (types seen: {len(types)})")
    draft = decode_stream(stream, theme2source)
    draft_score = text_score_wordlist([lower_letters_only(w) for w in words_from_stream(tokenize_mixed(draft))])
    print(f"Initial draft score: {draft_score:.4f}")

    # optimize
    best_map, best_score = optimize_map(stream, theme2source, iters=args.iters, seed=args.seed)
    best_text = decode_stream(stream, best_map)

    # save artifacts
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("./IpsumToLanguage", exist_ok=True)
    os.makedirs("./mappings", exist_ok=True)

    out_txt = f"./IpsumToLanguage/guessed_{stamp}.txt"
    out_map = f"./mappings/guessed_map_{stamp}.json"

    with io.open(out_txt, "w", encoding="utf-8") as f:
        f.write(best_text)

    meta = {
        "theme_key": args.theme_key,
        "assumed_src_lang": args.src,
        "created_at": stamp,
        "note": "Guessed mapping via length+freq initialization + annealed pair-swap optimization.",
        "score": best_score
    }
    with io.open(out_map, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "theme_to_source": best_map}, f, ensure_ascii=False, indent=2)

    print("\n=== DONE ===")
    print(f"Best score: {best_score:.4f}")
    print(f"Saved draft: {out_txt}")
    print(f"Saved map  : {out_map}")

if __name__ == "__main__":
    main()
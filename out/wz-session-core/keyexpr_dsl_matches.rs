// SCE-GENERATED — DO NOT EDIT
// source-hash: efe483b8c23efdefdaa54278e5db4cf384518b44642a21e3544dccee9803aa15
// SCE-MAP: keyexpr_dsl_matches.scxml:20 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_dsl_matches(p: &[u8], ps: u32, pe: u32, t: &[u8], ts: u32, te: u32) -> bool {
    if pe > (p).len() as u32 {
        return false;
    }
    if te > (t).len() as u32 {
        return false;
    }
    if ps > pe {
        return false;
    }
    if ts > te {
        return false;
    }
    let mut r: u32 = ts;
    let mut seg: u32 = ps;
    let mut first: bool = true;
    while seg <= pe {
        let mut q: u32 = seg;
        let mut last: bool = true;
        let mut after: u32 = pe;
        while last && q < pe {
            let mut star: bool = false;
            if p[(q) as usize] == 36 {
                let q1: u32 = q + 1;
                if q1 < pe {
                    if p[(q1) as usize] == 42 {
                        star = true;
                        after = q1 + 1;
                    }
                }
            }
            if star {
                last = false;
            } else {
                q = q + 1;
            }
        }
        if first {
            let mut lk: u32 = seg;
            let mut lx: u32 = r;
            while lk < q {
                if lx >= te {
                    return false;
                }
                if p[(lk) as usize] != t[(lx) as usize] {
                    return false;
                }
                lk = lk + 1;
                lx = lx + 1;
            }
            r = lx;
            first = false;
            if last {
                return false;
            }
        } else {
            if last {
                if seg == q {
                    return true;
                }
                let mut ts_: u32 = r;
                while ts_ < te {
                    let mut tk: u32 = seg;
                    let mut tx: u32 = ts_;
                    let mut tsame: bool = true;
                    while tsame && tk < q {
                        if tx >= te {
                            tsame = false;
                        } else {
                            if p[(tk) as usize] != t[(tx) as usize] {
                                tsame = false;
                            } else {
                                tk = tk + 1;
                                tx = tx + 1;
                            }
                        }
                    }
                    if tsame && tx == te {
                        return true;
                    }
                    ts_ = ts_ + 1;
                }
                return false;
            } else {
                if seg < q {
                    let mut mfound: bool = false;
                    let mut ms: u32 = r;
                    while !mfound && ms < te {
                        let mut mk: u32 = seg;
                        let mut mx: u32 = ms;
                        let mut msame: bool = true;
                        while msame && mk < q {
                            if mx >= te {
                                msame = false;
                            } else {
                                if p[(mk) as usize] != t[(mx) as usize] {
                                    msame = false;
                                } else {
                                    mk = mk + 1;
                                    mx = mx + 1;
                                }
                            }
                        }
                        if msame {
                            r = mx;
                            mfound = true;
                        } else {
                            ms = ms + 1;
                        }
                    }
                    if !mfound {
                        return false;
                    }
                }
            }
        }
        seg = after;
    }
    return false;
}
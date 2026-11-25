// SCE-GENERATED — DO NOT EDIT
// source-hash: aa21fdb1164921b3b8e970cd4b8e856c31ff96dd9b9a0552c78ae42f3aca1d81
// source: keyexpr_dsl_matches.scxml
// SCE-MAP: keyexpr_dsl_matches.scxml:20 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: sce_forge_runtime
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_dsl_matches(p: &[u8], ps: u32, pe: u32, t: &[u8], ts: u32, te: u32) -> bool {
    if pe > p.len() as u32 {
        return false;
    }
    if te > t.len() as u32 {
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
            if sce_forge_runtime::algorithm::proven::at(&p, q) == 36 {
                let q1: u32 = sce_forge_runtime::algorithm::proven::add::<u32>(q, 1);
                if q1 < pe {
                    if sce_forge_runtime::algorithm::proven::at(&p, q1) == 42 {
                        star = true;
                        after = sce_forge_runtime::algorithm::proven::add::<u32>(q1, 1);
                    }
                }
            }
            if star {
                last = false;
            } else {
                q = sce_forge_runtime::algorithm::proven::add::<u32>(q, 1);
            }
        }
        if first {
            let mut lk: u32 = seg;
            let mut lx: u32 = r;
            while lk < q {
                if lx >= te {
                    return false;
                }
                if sce_forge_runtime::algorithm::proven::at(&p, lk) != sce_forge_runtime::algorithm::proven::at(&t, lx) {
                    return false;
                }
                lk = sce_forge_runtime::algorithm::proven::add::<u32>(lk, 1);
                lx = sce_forge_runtime::algorithm::proven::add::<u32>(lx, 1);
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
                            if sce_forge_runtime::algorithm::proven::at(&p, tk) != sce_forge_runtime::algorithm::proven::at(&t, tx) {
                                tsame = false;
                            } else {
                                tk = sce_forge_runtime::algorithm::proven::add::<u32>(tk, 1);
                                tx = sce_forge_runtime::algorithm::proven::add::<u32>(tx, 1);
                            }
                        }
                    }
                    if tsame && tx == te {
                        return true;
                    }
                    ts_ = sce_forge_runtime::algorithm::proven::add::<u32>(ts_, 1);
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
                                if sce_forge_runtime::algorithm::proven::at(&p, mk) != sce_forge_runtime::algorithm::proven::at(&t, mx) {
                                    msame = false;
                                } else {
                                    mk = sce_forge_runtime::algorithm::proven::add::<u32>(mk, 1);
                                    mx = sce_forge_runtime::algorithm::proven::add::<u32>(mx, 1);
                                }
                            }
                        }
                        if msame {
                            r = mx;
                            mfound = true;
                        } else {
                            ms = sce_forge_runtime::algorithm::proven::add::<u32>(ms, 1);
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
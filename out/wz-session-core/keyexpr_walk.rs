// SCE-GENERATED — DO NOT EDIT
// source-hash: cc02b4dba071f4fdc21b539ee37b42dc67d2f985b8209cb58f3f55cbe8bcbd24
// SCE-MAP: keyexpr_walk.scxml:37 :: _forge_body

// SCE Forge: Auto-generated from Extended SCXML (sce:kind="algorithm")
// Runtime: none
// Do not edit — regenerate from the source SCXML file.
//
// RFC §synth-5-A: pure synchronous function with bounded loops. Free
// function, no instance state. `#![no_std]`-clean when no `bytes`
// parameter (this fixture: no_std_clean = false).

use super::keyexpr_chunk_end;
use super::keyexpr_chunk_kind;
use super::keyexpr_chunk_matches;
use super::keyexpr_chunk_intersects;
use super::keyexpr_chunk_includes;

#[allow(clippy::all)]
#[allow(unused_assignments)]
pub fn keyexpr_walk(p: &[u8], t: &[u8], relation: u8, wild_single: bool, wild_double: bool, wild_dsl: bool) -> u8 {
    let pn: u32 = (p).len() as u32;
    let tn: u32 = (t).len() as u32;
    let t_stops: bool = relation != 0 && wild_double;
    let mut ts: u32 = 0;
    let mut te: u32 = keyexpr_chunk_end::keyexpr_chunk_end(t, 0);
    let mut t_more: bool = true;
    if te == 0 {
        return 0;
    }
    if t_stops && keyexpr_chunk_kind::keyexpr_chunk_kind(t, 0, te) == 2 {
        return 2;
    }
    let mut ps: u32 = 0;
    let mut pe: u32 = keyexpr_chunk_end::keyexpr_chunk_end(p, 0);
    if pe == 0 {
        return 0;
    }
    let mut pkind: u8 = keyexpr_chunk_kind::keyexpr_chunk_kind(p, 0, pe);
    let mut p_more: bool = true;
    let mut frame: bool = false;
    let mut frame_ps: u32 = 0;
    let mut frame_pe: u32 = 0;
    let mut frame_pkind: u8 = 0;
    let mut frame_p_more: bool = false;
    let mut frame_ts: u32 = 0;
    while t_more {
        let mut advanced: bool = false;
        let mut t_next: u32 = ts;
        if p_more {
            let mut take: bool = false;
            let star_star: bool = wild_double && pkind == 2;
            if !star_star {
                if relation == 1 {
                    take = keyexpr_chunk_intersects::keyexpr_chunk_intersects(p, ps, pe, t, ts, te, wild_single, wild_dsl);
                } else {
                    if relation == 2 {
                        take = keyexpr_chunk_includes::keyexpr_chunk_includes(p, ps, pe, t, ts, te, wild_single, wild_dsl);
                    } else {
                        if wild_single && pkind == 1 {
                            take = keyexpr_chunk_kind::keyexpr_chunk_kind(t, ts, te) != 3;
                        } else {
                            take = keyexpr_chunk_matches::keyexpr_chunk_matches(p, ps, pe, t, ts, te, wild_dsl);
                        }
                    }
                }
            }
            if star_star || take {
                if pe < pn {
                    ps = pe + 1;
                    pe = keyexpr_chunk_end::keyexpr_chunk_end(p, ps);
                    if ps == pe {
                        return 0;
                    }
                    pkind = keyexpr_chunk_kind::keyexpr_chunk_kind(p, ps, pe);
                } else {
                    p_more = false;
                }
                advanced = true;
            }
            if star_star {
                frame = true;
                frame_ps = ps;
                frame_pe = pe;
                frame_pkind = pkind;
                frame_p_more = p_more;
                frame_ts = ts;
            }
            if take {
                if te < tn {
                    t_next = te + 1;
                } else {
                    t_more = false;
                }
            }
        }
        if !advanced {
            if !frame {
                return 0;
            }
            let fe: u32 = keyexpr_chunk_end::keyexpr_chunk_end(t, frame_ts);
            if keyexpr_chunk_kind::keyexpr_chunk_kind(t, frame_ts, fe) == 3 {
                return 0;
            }
            if fe < tn {
                frame_ts = fe + 1;
                t_next = frame_ts;
            } else {
                t_more = false;
            }
            ps = frame_ps;
            pe = frame_pe;
            pkind = frame_pkind;
            p_more = frame_p_more;
        }
        if t_more && t_next != ts {
            ts = t_next;
            te = keyexpr_chunk_end::keyexpr_chunk_end(t, ts);
            if ts == te {
                return 0;
            }
            if t_stops && keyexpr_chunk_kind::keyexpr_chunk_kind(t, ts, te) == 2 {
                return 2;
            }
        }
    }
    while p_more {
        if !(wild_double && pkind == 2) {
            return 0;
        }
        if pe < pn {
            ps = pe + 1;
            pe = keyexpr_chunk_end::keyexpr_chunk_end(p, ps);
            if ps == pe {
                return 0;
            }
            pkind = keyexpr_chunk_kind::keyexpr_chunk_kind(p, ps, pe);
        } else {
            p_more = false;
        }
    }
    return 1;
}
// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The helper macros of the family. Each is `#[macro_export]`, so it is at the crate root, and the
//! expansions are upstream's: they are the contract, since a crate that uses one expands this text.

/// A standard lock on a `Mutex<T>`.
#[macro_export]
macro_rules! zlock {
    ($var:expr) => {
        $var.lock().unwrap()
    };
}

/// A standard read on an `RwLock<T>`.
#[macro_export]
macro_rules! zread {
    ($var:expr) => {
        $var.read().unwrap()
    };
}

/// A standard write on an `RwLock<T>`.
#[macro_export]
macro_rules! zwrite {
    ($var:expr) => {
        $var.write().unwrap()
    };
}

/// An async lock on a `Mutex<T>`.
#[macro_export]
macro_rules! zasynclock {
    ($var:expr) => {
        $var.lock().await
    };
}

/// An async read on an `RwLock<T>`: `try_read` first, and `read().await` when that fails.
#[macro_export]
macro_rules! zasyncread {
    ($var:expr) => {
        if let Ok(g) = $var.try_read() {
            g
        } else {
            $var.read().await
        }
    };
}

/// An async write on an `RwLock<T>`: `try_write` first, and `write().await` when that fails.
#[macro_export]
macro_rules! zasyncwrite {
    ($var:expr) => {
        if let Ok(g) = $var.try_write() {
            g
        } else {
            $var.write().await
        }
    };
}

/// `&T` from an `RwLock<Option<T>>`, which it assumes holds `Some`.
#[macro_export]
macro_rules! zasyncopt {
    ($var:expr) => {
        zasyncread!($var).as_ref().unwrap()
    };
}

/// An async send on a channel: `try_send` first, and `send().await` when that fails.
#[macro_export]
macro_rules! zasyncsend {
    ($ch:expr, $var:expr) => {
        if $ch.try_send($var).is_err() {
            $ch.send($var).await;
        }
    };
}

/// An async receive on a channel: `try_recv` first, and `recv().await` when that fails.
#[macro_export]
macro_rules! zasyncrecv {
    ($ch:expr) => {
        if let Ok(v) = $ch.try_recv() {
            Ok(v)
        } else {
            $ch.recv().await
        }
    };
}

/// Static constants that a build can override: each `static ref NAME: T = default;` is read from the
/// environment variable `NAME` at compile time when it is set, and is `default` otherwise.
#[macro_export]
macro_rules! zconfigurable {
    ($(#[$attr:meta])* static ref $N:ident : $T:ty = $e:expr; $($t:tt)*) => {
        $(#[$attr])* $crate::lazy_static!(static ref $N : $T = match option_env!(stringify!($N)) {
            Some(value) => {value.parse().unwrap()}
            None => {$e}
        };) ;
        $crate::zconfigurable!($($t)*);
    };
    ($(#[$attr:meta])* pub static ref $N:ident : $T:ty = $e:expr; $($t:tt)*) => {
        $(#[$attr])* $crate::lazy_static!(pub static ref $N : $T = match option_env!(stringify!($N)) {
            Some(value) => {value.parse().unwrap()}
            None => {$e}
        };) ;
        $crate::zconfigurable!($($t)*);
    };
    ($(#[$attr:meta])* pub ($($vis:tt)+) static ref $N:ident : $T:ty = $e:expr; $($t:tt)*) => {
        $(#[$attr])* $crate::lazy_static!(pub ($($vis)+) static ref $N : $T = match option_env!(stringify!($N)) {
            Some(value) => {value.parse().unwrap()}
            None => {$e}
        };) ;
        $crate::zconfigurable!($($t)*);
    };
    () => ()
}

/// The conversion to `u64`, panicking when the value does not fit. It needs `TryFrom` in scope.
#[macro_export]
macro_rules! to_u64 {
    ($val:expr) => {
        u64::try_from($val).unwrap_or_else(|_| {
            panic!(
                "Can not encode {} as u64 (max u64 value: {})",
                $val,
                u64::MAX
            )
        })
    };
}

/// Parse a string to the target type, logging and returning an error when it does not parse.
#[macro_export]
macro_rules! zparse {
    ($str:expr) => {
        $str.parse().map_err(|_| {
            let e = zenoh_result::zerror!(
                "Failed to read configuration: {} is not a valid value",
                $str
            );
            tracing::warn!("{}", e);
            e
        })
    };
}

/// Parse a string to the target type, logging when it does not parse and using `default` then.
#[macro_export]
macro_rules! zparse_default {
    ($str:expr, $default:expr) => {
        match $str.parse() {
            Ok(value) => value,
            Err(_) => {
                let e = zenoh_result::zerror!(
                    "Failed to read configuration: {} is not a valid value",
                    $str
                );
                tracing::warn!("{}", e);
                $default
            }
        }
    };
}

/// Conditional compilation on a feature of the crate that expands it: `$yes` with the feature and
/// `$not` without.
#[macro_export]
macro_rules! zcondfeat {
    ($feature:literal, $yes:expr, $not:expr) => {{
        {
            #[cfg(feature = $feature)]
            {
                $yes
            }

            #[cfg(not(feature = $feature))]
            {
                $not
            }
        }
    }};
}

/// Time a future out after the caller's `TIMEOUT`, and unwrap it.
#[macro_export]
macro_rules! ztimeout {
    ($f:expr) => {
        tokio::time::timeout(TIMEOUT, ::core::future::IntoFuture::into_future($f))
            .await
            .unwrap()
    };
}

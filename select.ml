open Core.Std
open Async.Std

(** we need something like "select" *)

let choice1 = choice (after (sec 0.5)) (fun () -> `First)

let choice2 = choice (after (sec 0.500001)) (fun () -> `Second)

let test () =
  choose [choice1; choice2] >>=
  function
  | `First -> return (print_endline "first this time"); 
  | `Second -> return (print_endline "Second")

let () = (test () >>= fun () -> exit 0) |> don't_wait_for

let () = never_returns (Scheduler.go ())
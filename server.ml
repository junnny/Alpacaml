open Core.Std
open Async.Std

(*
socks proxy, 
tcp server on the client side
*)

module Fd = Unix.Fd
module Inet_addr = Unix.Inet_addr
module Socket = Unix.Socket

let stdout_writer = Lazy.force Writer.stdout
let message s = Writer.write stdout_writer s

let finished () = shutdown 0

let listening_port = 61111


(* write back directly *)
let server =
  Core.Std.eprintf "Server starts listening\n%!";
  Tcp.Server.create (Tcp.on_port listening_port)
    (fun _ reader writer ->
      Deferred.create (fun finished ->
        let rec loop () =
          upon (Reader.read_line reader) (function
          | `Ok query ->
            message (sprintf "Server got query: %s\n" query);
            Writer.write writer query;
            loop ()
          | `Eof ->
            Ivar.fill finished ();
            message "Server got EOF\n")
        in
        loop ()))
;;


let () = never_returns (Scheduler.go ())

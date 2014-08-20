open Core.Std
open Async.Std

let host = ["www.gutenberg.org/cache/epub/2600/pg2600.txt"; "www.bilibili.tv"; "www.zhihu.com"]

let rec dns_lookup domains =
  match domains with
  | [] -> print_endline "Finished"; exit 0
  | x :: res -> 
     Unix.Inet_addr.of_string_or_getbyname x >>=
     (fun addr -> 
        printf "%s: " x; Unix.Inet_addr.to_string addr |> print_endline;
        dns_lookup res)


let () = don't_wait_for (dns_lookup host)

let () = never_returns (Scheduler.go ())

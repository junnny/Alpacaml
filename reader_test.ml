open Core.Std
open Async.Std

let reader_of_string ?buf_len str =
  Unix.pipe (Info.of_string "Reader test")
  >>= fun (`Reader reader_fd, `Writer writer_fd) ->
  let reader = Reader.create reader_fd ?buf_len
  and writer = Writer.create writer_fd in
  Writer.write writer str;
  don't_wait_for (Writer.close writer);
  return reader
;;

let assert_equal l r = assert (l = r)
;;

let read_partial_chunks () =
  reader_of_string "0123456789" ~buf_len:5
  >>= fun reader ->
  let step = ref 0 in
  Reader.read_one_chunk_at_a_time reader
    ~handle_chunk:(fun buf ~pos ~len ->
      incr step;
      match !step with
      | 1 -> begin
         assert_equal 0 pos;
         assert_equal 5 len;
         assert_equal "01234" (Bigstring.to_string buf ~pos ~len);
         return (`Consumed (4, `Need_unknown))
         end
      | 2 -> begin
         assert_equal 0 pos;
         assert_equal 5 len;
         assert_equal "45678" (Bigstring.to_string buf ~pos ~len);
         return (`Consumed (3, `Need_unknown))
         end
      | 3 -> begin
         assert_equal 0 pos;
         assert_equal 3 len;
         assert_equal "789" (Bigstring.to_string buf ~pos ~len);
         return (`Stop ()) 
         end
      | _ -> assert false
   ) >>= fun res -> assert_equal (`Stopped ()) res; Reader.close reader
;;

let () = don't_wait_for (read_partial_chunks ())
;;

let () = never_returns (Scheduler.go ())
;;


         
         


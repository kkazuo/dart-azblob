open Cohttp

module Conn: sig
  type t = {
    key: string;
    name: string;
    protocol: string;
    suffix: string;
  }

  (** [init] returns default. *)
  val init : t

  (** [parse_exn] parses a connection string and returns [t]. *)
  val parse_exn : string -> t
end

(** The version of Azure Blob Storage API *)
val ms_version : string

(** [uri] makes blob uri. *)
val uri : ?path:string -> ?query:(string * string list) list -> Conn.t -> Uri.t

(** [sign_header_exn] signs request header. *)
val sign_header_exn : ?content_length:int64 ->
  ?path:string ->
  ?query:(string * string list) list ->
  Conn.t -> Code.meth -> Header.t -> Header.t

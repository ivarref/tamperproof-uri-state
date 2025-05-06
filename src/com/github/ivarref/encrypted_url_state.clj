(ns com.github.ivarref.encrypted-url-state
  (:require [taoensso.nippy :as nippy])
  (:import
    (java.util Base64)))

(declare encrypt-to-bytes)

(def ^:dynamic ^:private -*current-epoch-time*
  (fn []
    (long (/ (System/currentTimeMillis)
             1000))))

(defn encrypt
  ([secret-key state]
   (when (not (string? secret-key))
     (throw (IllegalArgumentException. "secret-key must be a string")))
   (encrypt secret-key (+ (-*current-epoch-time*) 3600) state))
  ([secret-key exp-epoch-seconds state]
   (.encodeToString (Base64/getUrlEncoder) (encrypt-to-bytes secret-key exp-epoch-seconds state))))

(defn encrypt-to-bytes [secret-key exp-epoch-seconds state]
  (when (not (string? secret-key))
    (throw (IllegalArgumentException. "secret-key must be a string")))
  (when (not (number? exp-epoch-seconds))
    (throw (IllegalArgumentException. "exp-epoch-seconds must be a number")))
  (nippy/freeze [(long exp-epoch-seconds) state] {:password [:cached secret-key]}))

(defn decrypt-to-map
  ([secret-key encrypted-str-b64-url]
   (when (not (string? secret-key))
    (throw (IllegalArgumentException. "secret-key must be a string")))
   (when (not (or (bytes? encrypted-str-b64-url) (string? encrypted-str-b64-url)))
     (throw (IllegalArgumentException. "encrypted-str-b64-url must be a string or bytes")))
   (decrypt-to-map secret-key (-*current-epoch-time*) encrypted-str-b64-url))
  ([secret-key epoch-seconds-now encrypted-str-b64-url]
   (when (not (string? secret-key))
     (throw (IllegalArgumentException. "secret-key must be a string")))
   (when-not (number? epoch-seconds-now)
     (throw (IllegalArgumentException. "epoch-seconds-now must be a number")))
   (when (not (or (bytes? encrypted-str-b64-url) (string? encrypted-str-b64-url)))
     (throw (IllegalArgumentException. "encrypted-str-b64-url must be a string or bytes")))
   (let [[error payload] (try
                           [false (nippy/thaw (if (string? encrypted-str-b64-url)
                                                (.decode (Base64/getUrlDecoder) ^String encrypted-str-b64-url)
                                                encrypted-str-b64-url)
                                              {:password [:cached secret-key]})]
                           (catch Exception e
                             [true (or (ex-message e) "empty error message")]))]
     (if (true? error)
       {:expired? false :data nil :error? true :error-message payload}
       (do
         (assert (and (vector? payload)
                      (= 2 (count payload))
                      (int? (first payload))))
         (let [[expiry data] payload
               expired? (> (long epoch-seconds-now) expiry)]
           (if expired?
             {:expired? true :data nil :error? true :error-message "Expired"}
             {:expired? false :data data :error? false :error-message nil})))))))

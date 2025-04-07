(ns com.github.ivarref.tamperproof-uri-state
  (:require [clojure.java.io :as io]
            [clojure.string :as str])
  (:import (java.io File)
           (java.nio.charset StandardCharsets)
           (java.util Base64)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)))

(comment
  (set! *warn-on-reflection* true))

(def algorithm "HmacSHA256")

(defn- str->bytes [s]
  (assert (string? s))
  (.getBytes ^String s StandardCharsets/UTF_8))

(defn- bytes->uri-str [b]
  (assert (bytes? b))
  (let [encoder (Base64/getUrlEncoder)]
    (.encodeToString encoder b)))

(defn- plaintext->uri-str [plaintext]
  (assert (string? plaintext))
  (let [encoder (Base64/getUrlEncoder)]
    (.encodeToString encoder (str->bytes plaintext))))

(defn- get-key-bytes [key]
  (when (and (string? key) (.exists ^File (io/file key)))
    (throw (IllegalStateException. (str "key cannot be a file!"))))
  (cond (bytes? key) key
        (string? key) (str->bytes key)
        :else (throw (IllegalArgumentException. (str "Unhandled key type: " (type key))))))

(defn- get-hash-bytes [key plaintext]
  (when (nil? key)
    (throw (IllegalArgumentException. "key cannot be nil")))
  (when (not (string? plaintext))
    (throw (IllegalArgumentException. "plaintext must be string")))
  (let [key (get-key-bytes key)
        secret-key (SecretKeySpec. key algorithm)
        mac (Mac/getInstance algorithm)]
    (.init mac secret-key)
    (.doFinal mac (str->bytes plaintext))))

(defn plus-now [seconds]
  (+ (long (/ (System/currentTimeMillis) 1000))
     (long seconds)))

(defn now-plus [seconds]
  (plus-now seconds))

(defn now []
  (plus-now 0))

(defn sign [private-key exp-epoch-seconds state]
  (assert (or (bytes? private-key) (string? private-key)) "private-key must be byte array or string")
  (assert (string? state) "state must be a string")
  (let [exp-epoch-seconds (if (number? exp-epoch-seconds)
                            (long exp-epoch-seconds)
                            (throw (IllegalArgumentException. (str "Do not know how to handle exp-epoch-seconds argument: " exp-epoch-seconds))))
        epoch-bytes (.toByteArray (BigInteger. (str exp-epoch-seconds) 10))
        state-with-expiry (str (plaintext->uri-str state)
                               "."
                               (bytes->uri-str epoch-bytes))
        signature (bytes->uri-str (get-hash-bytes private-key state-with-expiry))]
    (str state-with-expiry "." signature)))

(def ^:dynamic *is-test* false)

(defn unsign
  ([private-key state-with-hash]
   (unsign private-key (now) state-with-hash))
  ([private-key now-epoch-seconds state-with-hash]
   (assert (or (bytes? private-key) (string? private-key)) "private-key must be byte array or string")
   (assert (string? state-with-hash))
   (assert (number? now-epoch-seconds))
   (assert (= 3 (count (str/split state-with-hash #"\.")))
           "Expected state-with-hash to contain exactly three period characters")
   (let [now-epoch-seconds (long now-epoch-seconds)
         key-bytes (get-key-bytes private-key)
         [msg-enc exp-enc signature-input] (str/split state-with-hash #"\.")
         msg (str msg-enc "." exp-enc)
         signature (bytes->uri-str (get-hash-bytes key-bytes msg))
         exp-epoch-seconds (.longValue (BigInteger. #^bytes (.decode (Base64/getUrlDecoder) ^String exp-enc)))]
     (cond
       (and (not= signature-input signature)
            (> now-epoch-seconds exp-epoch-seconds))
       (if (true? *is-test*) :incorrect-signature+expired nil)

       (not= signature-input signature)
       (if (true? *is-test*) :incorrect-signature nil)

       (> now-epoch-seconds exp-epoch-seconds)
       (if (true? *is-test*) [:expired exp-epoch-seconds] nil)

       (= signature-input signature)
       (String. (.decode (Base64/getUrlDecoder) ^String msg-enc) StandardCharsets/UTF_8)

       :else
       (throw (IllegalStateException. "Unexpected state"))))))

(defn unsign-to-map
  ([private-key state-with-hash]
   (unsign-to-map private-key (now) state-with-hash))
  ([private-key now-epoch-seconds state-with-hash]
   (binding [*is-test* true]
     (let [res (unsign private-key now-epoch-seconds state-with-hash)]
       (cond
         (= :incorrect-signature+expired res)
         {:tampered? true :expired? true :state nil}

         (= :incorrect-signature res)
         {:tampered? true :expired? false :state nil}

         (and (vector? res)
              (= 2 (count res))
              (= :expired (first res)))
         {:tampered? false :expired? true :state nil}

         (string? res)
         {:tampered? false :expired? false :state res}

         :else
         (throw (IllegalStateException. "Unexpected state unsign-verb")))))))

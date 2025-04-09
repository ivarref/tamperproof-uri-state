(ns com.github.ivarref.encrypted-uri-state
  (:import (java.io ByteArrayInputStream ByteArrayOutputStream InputStream)
           (java.nio.charset StandardCharsets)
           (java.security Key SecureRandom)
           (java.security.spec AlgorithmParameterSpec)
           (java.util Base64)
           (javax.crypto Cipher SecretKeyFactory)
           (javax.crypto.spec GCMParameterSpec PBEKeySpec SecretKeySpec)))

(when (= "true" (System/getProperty "encrypted_uri_state.warn.on.reflection" "false"))
  (println "set! *warn-on-reflection* to true")
  (set! *warn-on-reflection* true))

(defn- str-bytes [^String s]
  (.getBytes s StandardCharsets/UTF_8))

(defn- generate-iv-bytes []
  (let [iv (byte-array 12)]
    (.nextBytes (SecureRandom.) iv)
    iv))

(defn- get-key-from-password-and-salt [password salt]
  (let [secret-key-factory (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA256")
        key-spec (PBEKeySpec. (.toCharArray ^String password) (str-bytes salt) 600000 256) ; https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        secret-key (SecretKeySpec. (.getEncoded (.generateSecret secret-key-factory key-spec)) "AES")]
    secret-key))

(defn- get-key-from-salt [salt]
  (let [secret-key-factory (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA256")
        key-spec (PBEKeySpec. nil (str-bytes salt) 600000 256) ; https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        secret-key (SecretKeySpec. (.getEncoded (.generateSecret secret-key-factory key-spec)) "AES")]
    secret-key))

(def cipher-type "AES/GCM/Nopadding")

(defn- concat-byte-arrays [vec-of-arrays]
  (assert (vector? vec-of-arrays))
  (with-open [baos (ByteArrayOutputStream.)]
    (doseq [ar vec-of-arrays]
      (assert (bytes? ar))
      (.write baos #^bytes ar))
    (.toByteArray baos)))

(defn- encode-epoch-seconds [exp-epoch-seconds]
  (let [number-byte-array (.toByteArray (BigInteger. (str exp-epoch-seconds) 10))
        num-of-bytes (alength number-byte-array)]
    (assert (<= num-of-bytes 255))
    (assert (>= num-of-bytes 1))
    (let [exp-epoch-seconds-encoded (concat-byte-arrays [(byte-array [(byte num-of-bytes)])
                                                         number-byte-array])]
      exp-epoch-seconds-encoded)))

(defn get-secret-key [secret-key]
  (cond
    (instance? SecretKeySpec secret-key)
    secret-key

    (and (vector? secret-key)
         (= 2 (count secret-key)))
    (get-key-from-password-and-salt (first secret-key) (second secret-key))

    (string? secret-key)
    (get-key-from-salt secret-key)

    :else
    (throw (IllegalArgumentException. "Cannot make use of secret-key"))))

(defn encrypt [secret-key exp-epoch-seconds plaintext]
  (let [secret-key (get-secret-key secret-key)]
    (assert (instance? Key secret-key))
    (assert (number? exp-epoch-seconds))
    (assert (string? plaintext))
    (let [exp-epoch-seconds (long exp-epoch-seconds)
          iv-bytes (generate-iv-bytes)
          iv (GCMParameterSpec. 128 iv-bytes)
          cipher (Cipher/getInstance cipher-type)
          _ (.init cipher Cipher/ENCRYPT_MODE ^Key secret-key ^AlgorithmParameterSpec iv)
          cipher-text-bytes (.doFinal cipher (concat-byte-arrays [(encode-epoch-seconds exp-epoch-seconds) (str-bytes plaintext)]))
          cipher-bytes (concat-byte-arrays [iv-bytes cipher-text-bytes])]
      (.encodeToString (Base64/getUrlEncoder) cipher-bytes))))

(defn- read-n-bytes [^InputStream bais n]
  (with-open [baos (ByteArrayOutputStream.)]
    (loop [i 0]
      (let [byt (.read ^ByteArrayInputStream bais)]
        (assert (not= -1 byt))
        (.write baos ^int byt)
        (if (= i (dec n))
          (do
            (assert (= n (alength (.toByteArray baos))))
            (.toByteArray baos))
          (recur (inc i)))))))

(defn- split-bytes-at [byte-ar n]
  (assert (bytes? byte-ar))
  (assert (pos-int? n))
  (with-open [left (ByteArrayOutputStream.)
              right (ByteArrayOutputStream.)]
    (dotimes [i (alength #^bytes byte-ar)]
      (if (>= i n)
        (.write right ^int (aget #^bytes byte-ar i))
        (.write left ^int (aget #^bytes byte-ar i))))
    [(.toByteArray left) (.toByteArray right)]))

(defn- skip-n-bytes [byte-ar n]
  (assert (bytes? byte-ar))
  (assert (pos-int? n))
  (with-open [baos (ByteArrayOutputStream.)]
    (dotimes [i (alength #^bytes byte-ar)]
      (when (>= i n)
        (.write baos ^int (aget #^bytes byte-ar i))))
    (.toByteArray baos)))

(defn- max-n-bytes [byte-ar n]
  (assert (bytes? byte-ar))
  (assert (pos-int? n))
  (with-open [baos (ByteArrayOutputStream.)]
    (dotimes [i (alength #^bytes byte-ar)]
      (when (< i n)
        (.write baos ^int (aget #^bytes byte-ar i))))
    (.toByteArray baos)))

(defn- decrypted-bytes->exp [decrypted-bytes]
  (assert (bytes? decrypted-bytes))
  (let [exp-len (aget #^bytes decrypted-bytes 0)]
    (assert (pos-int? exp-len))
    (let [epoch-bytes (max-n-bytes (skip-n-bytes decrypted-bytes 1) exp-len)
          epoch-seconds (BigInteger. #^bytes epoch-bytes)]
      (long epoch-seconds))))

(defn- decrypted-bytes->state [decrypted-bytes]
  (assert (bytes? decrypted-bytes))
  (let [exp-len (aget #^bytes decrypted-bytes 0)]
    (assert (pos-int? exp-len))
    (String. #^bytes (skip-n-bytes decrypted-bytes (+ exp-len 1)) StandardCharsets/UTF_8)))

(defn- decrypt-to-vec [secret-key encrypted-str-b64]
  (assert (string? encrypted-str-b64))
  (let [secret-key (get-secret-key secret-key)]
    (let [encrypted-bytes (.decode (Base64/getUrlDecoder) ^String encrypted-str-b64)
          cipher (Cipher/getInstance cipher-type)
          [iv-bytes encrypted-bytes-without-iv] (split-bytes-at encrypted-bytes 12)
          _ (.init cipher Cipher/DECRYPT_MODE ^Key secret-key (GCMParameterSpec. 128 iv-bytes))
          decrypted-bytes (.doFinal cipher encrypted-bytes-without-iv)]
      [(decrypted-bytes->exp decrypted-bytes)
       (decrypted-bytes->state decrypted-bytes)
       nil])))

(defn decrypt-to-map [secret-key epoch-seconds-now encrypted-str-b64-url]
  (when-not (number? epoch-seconds-now)
    (throw (IllegalArgumentException. "epoch-seconds-now must be a number")))
  (when-not (string? encrypted-str-b64-url)
    (throw (IllegalArgumentException. "encrypted-str-b64-url must be a string")))
  (assert (string? encrypted-str-b64-url))
  (assert (number? epoch-seconds-now))
  (let [epoch-seconds-now (long epoch-seconds-now)
        [expiry state error] (try
                               (decrypt-to-vec secret-key encrypted-str-b64-url)
                               (catch Exception e
                                 [false nil (or (ex-message e) "empty error message")]))]
    (if error
      {:expired? false :state nil :error? true :error-message error}
      (let [expired? (> epoch-seconds-now expiry)]
        (if expired?
          {:expired? true :state nil :error? false :error-message nil}
          {:expired? false :state state :error? false :error-message nil})))))

(ns com.github.ivarref.encrypted-uri-state
  (:import (java.io ByteArrayInputStream ByteArrayOutputStream InputStream)
           (java.nio.charset StandardCharsets)
           (java.security Key KeyFactory SecureRandom)
           (java.security.spec AlgorithmParameterSpec PKCS8EncodedKeySpec)
           (java.util Base64)
           (javax.crypto Cipher SecretKeyFactory)
           (javax.crypto.spec GCMParameterSpec PBEKeySpec SecretKeySpec)))

(when (= "true" (System/getProperty "tamperproof.warn.on.reflection" "false"))
  (set! *warn-on-reflection* true))

(defn- str-bytes [^String s]
  (.getBytes s StandardCharsets/UTF_8))

(defn- print-bytes [byts]
  (assert (bytes? byts))
  (dotimes [i (alength #^bytes byts)]
    (print (format "%02x" (byte (aget #^bytes byts i))))
    (print " "))
  (println "")
  (flush))

(defn get-key-from-password [password salt]
  (let [secret-key-factory (SecretKeyFactory/getInstance "PBKDF2WithHmacSHA256")
        key-spec (PBEKeySpec. (.toCharArray ^String password) (str-bytes salt) 65536 256)
        secret-key (SecretKeySpec. (.getEncoded (.generateSecret secret-key-factory key-spec)) "AES")]
    secret-key))

(defn create-private-key [private-key-bytes]
  (let [key-factory (KeyFactory/getInstance "EC")
        private-key-spec (PKCS8EncodedKeySpec. private-key-bytes)]
    (.generatePrivate key-factory private-key-spec)))

(defn get-key-from-pkcs8 [pkcs8-string]
  (let [private-key-content (-> (slurp "ec256.pem")
                                (.replace "-----BEGIN PRIVATE KEY-----" "")
                                (.replace "-----END PRIVATE KEY-----" "")
                                (.replace "\n" ""))]
    (.decode (Base64/getDecoder) private-key-content)))


(defn- generate-iv-bytes []
  #_(byte-array [(byte 1)
                 (byte 2)
                 (byte 3)
                 (byte 4)
                 (byte 5)
                 (byte 6)
                 (byte 7)
                 (byte 8)
                 (byte 9)
                 (byte 10)
                 (byte 11)
                 (byte 12)])
  (let [iv (byte-array 12)]
    (.nextBytes (SecureRandom.) iv)
    iv))

(def cipher-type "AES/GCM/Nopadding")

(defn- concat-byte-arrays [vec-of-arrays]
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
      (print-bytes exp-epoch-seconds-encoded)
      exp-epoch-seconds-encoded)))

(defn encrypt [secret-key exp-epoch-seconds plaintext]
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
    (.encodeToString (Base64/getUrlEncoder) cipher-bytes)))


(defn read-n-bytes [^InputStream bais n]
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

(defn split-bytes-at [byte-ar n]
  (assert (bytes? byte-ar))
  (assert (pos-int? n))
  (with-open [left (ByteArrayOutputStream.)
              right (ByteArrayOutputStream.)]
    (dotimes [i (alength #^bytes byte-ar)]
      (if (>= i n)
        (.write right ^int (aget #^bytes byte-ar i))
        (.write left ^int (aget #^bytes byte-ar i))))
    [(.toByteArray left) (.toByteArray right)]))

(defn skip-n-bytes [byte-ar n]
  (assert (bytes? byte-ar))
  (assert (pos-int? n))
  (with-open [baos (ByteArrayOutputStream.)]
    (dotimes [i (alength #^bytes byte-ar)]
      (when (>= i n)
        (.write baos ^int (aget #^bytes byte-ar i))))
    (.toByteArray baos)))

(defn max-n-bytes [byte-ar n]
  (assert (bytes? byte-ar))
  (assert (pos-int? n))
  (with-open [baos (ByteArrayOutputStream.)]
    (dotimes [i (alength #^bytes byte-ar)]
      (when (< i n)
        (.write baos ^int (aget #^bytes byte-ar i))))
    (.toByteArray baos)))

(defn get-cipher-bytes [cipher-text-b64]
  (let [bytes-input (.decode (Base64/getUrlDecoder) ^String cipher-text-b64)]
    (print "get-cipher bytes: ")
    (print-bytes (max-n-bytes bytes-input 13))
    (with-open [bais (ByteArrayInputStream. bytes-input)
                baos (ByteArrayOutputStream.)]
      (read-n-bytes bais 12)
      (let [exp-epoch-seconds-len (byte (.read ^ByteArrayInputStream bais))]
        (println "decode exp-epoch-seconds-len:" exp-epoch-seconds-len)))))

(defn decrypt [secret-key encrypted-bytes]
  (assert (instance? SecretKeySpec secret-key))
  (assert (bytes? encrypted-bytes))
  (let [cipher (Cipher/getInstance cipher-type)
        [iv-bytes encrypted-bytes-without-iv] (split-bytes-at encrypted-bytes 12)
        _ (.init cipher Cipher/DECRYPT_MODE ^Key secret-key (GCMParameterSpec. 128 iv-bytes))
        decrypted-bytes (.doFinal cipher encrypted-bytes-without-iv)]
    decrypted-bytes))

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

(try
  (do
    (let [plaintext "omg-zoooomgw000tkebbelife"
          secret-key (get-key-from-password "my-key" "my-salt")]
      ;(println (encrypt secret-key plaintext))
      ;(println (encrypt secret-key plaintext))
      (let [enc (encrypt secret-key (/ (System/currentTimeMillis) 1000) plaintext)]
        (println enc "len:" (count enc)))
      #_(println (encrypt-str secret-key 3600 plaintext))
      #_(let [all-str (encrypt secret-key (/ (System/currentTimeMillis) 1000) "my-state")
              all-bytes (.decode (Base64/getUrlDecoder) ^String all-str)
              decrypted-bytes (decrypt secret-key all-bytes)]
          (print-bytes decrypted-bytes)
          (println (decrypted-bytes->exp decrypted-bytes))
          (println (long (/ (System/currentTimeMillis) 1000)))
          (println (decrypted-bytes->state decrypted-bytes))
          ;(print-bytes (skip-n-bytes encrypted-bytes 1))
          ;(print-bytes (skip-n-bytes encrypted-bytes 12))
          #_(get-cipher-bytes all-str))
      #_(println "janei:")
      #_(println (alength (.toByteArray (BigInteger. (str Long/MAX_VALUE) 10))))))

  (catch Exception e
    (println "Error:" (ex-message e))
    (throw e)))

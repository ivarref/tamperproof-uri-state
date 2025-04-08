(ns com.github.ivarref.encrypted-uri-state-test
  (:require [clojure.test :as t]
            [com.github.ivarref.encrypted-uri-state :as eus]))

(defn d [prefix x]
  (println prefix x)
  x)

(defn- generate-iv-bytes-mock []
  (byte-array [(byte 1)
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
               (byte 12)]))

(defn- generate-iv-bytes-mock-2 []
  (byte-array (vec (reverse [(byte 1)
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
                             (byte 12)]))))

(def secret-key ["my-key" "my-salt"])

(t/deftest basics
  (with-redefs [eus/generate-iv-bytes generate-iv-bytes-mock]
    (t/is (= "AQIDBAUGBwgJCgsMM2RxoI-hI7WTG0K8eHlrmiHhXT_67UhoYuLJWrjkc20Aen98kBg5hzQXttnFNoI="
             (eus/encrypt secret-key 1 "my-super-duper-great-message\n"))))

  (with-redefs [eus/generate-iv-bytes generate-iv-bytes-mock-2]
    (t/is (= "DAsKCQgHBgUEAwIBYB_uNgCNyB-0F1c9F0lgcXffanWSfU7EvEEOqIPgNdlCDicJpj4bxuGHqfqcMY0="
             (eus/encrypt secret-key 1 "my-super-duper-great-message\n"))))

  (eus/decrypt-to-bytes secret-key 0 "DAsKCQgHBgUEAwIBYB_uNgCNyB-0F1c9F0lgcXffanWSfU7EvEEOqIPgNdlCDicJpj4bxuGHqfqcMY0="))
#_(t/deftest unsign-to-map-test
    (let [state "my-super-duper-great-message\n"
          signed (tus/sign "my-key" 1 state)]

      (t/is (= {:tampered? false :expired? false :state state} (tus/unsign-to-map "my-key" 1 signed)))
      (t/is (= {:tampered? false :expired? true :state nil} (tus/unsign-to-map "my-key" 2 signed)))
      (t/is (= {:tampered? true :expired? false :state nil} (tus/unsign-to-map "my-kyz" 1 signed)))
      (t/is (= {:tampered? true :expired? true :state nil} (tus/unsign-to-map "my-kyz" 2 signed)))))

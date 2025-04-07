(ns com.github.ivarref.tamperproof-uri-state-test
  (:require [clojure.test :as t]
            [com.github.ivarref.tamperproof-uri-state :as tus]))

(t/deftest basics
  (t/is (= "bXktc3VwZXItZHVwZXItZ3JlYXQtbWVzc2FnZQo=.AQ==.OtCxxbiLSLdVH6uV8bgCBhVNitR4dncqvSsohEUyriM="
           (tus/sign "my-key" 1 "my-super-duper-great-message\n")))
  (t/is (= "bXktc3VwZXItZHVwZXItZ3JlYXQtbWVzc2FnZQo=.AA==.aTWZsVWi_tGMqPX92URFknT5r_sutWnGyAp9mDXtZTU="
           (tus/sign "my-key" 0 "my-super-duper-great-message\n")))
  (t/is (= "my-super-duper-great-message\n"
           (->> "my-super-duper-great-message\n"
                (tus/sign "my-key" 1)
                (tus/unsign "my-key" 1))))

  (let [incorrect-signature "bXktc3VwZXItZHVwZXItZ3JlYXQtbWVzc2FnZQo=.AA==.OtCxxbiLSLdVH6uV8bgCBhVNitR4dncqvSsohEUyriM="]
    (t/is (nil? (tus/unsign "my-key" 0 incorrect-signature)))
    (binding [tus/*is-test* true]
      (t/is (= :incorrect-signature
               (tus/unsign "my-key" 0 incorrect-signature)))))
  ; test expiration:
  (t/is (nil? (tus/unsign "my-key" 1 (tus/sign "my-key" 0 "my-super-duper-great-message\n"))))
  (binding [tus/*is-test* true]
    (t/is (= [:expired 0]
             (tus/unsign "my-key" 1 (tus/sign "my-key" 0 "my-super-duper-great-message\n"))))
    (t/is (= [:expired 123412341234]
             (tus/unsign "my-key" 123412341235 (tus/sign "my-key" 123412341234 "my-super-duper-great-message\n"))))))

(t/deftest unsign-to-map-test
  (let [state "my-super-duper-great-message\n"
        signed (tus/sign "my-key" 1 state)]

    (t/is (= {:tampered? false :expired? false :state state} (tus/unsign-to-map "my-key" 1 signed)))
    (t/is (= {:tampered? false :expired? true :state nil} (tus/unsign-to-map "my-key" 2 signed)))
    (t/is (= {:tampered? true :expired? false :state nil} (tus/unsign-to-map "my-kyz" 1 signed)))
    (t/is (= {:tampered? true :expired? true :state nil} (tus/unsign-to-map "my-kyz" 2 signed)))))

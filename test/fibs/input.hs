{-# NOINLINE fibs #-}
fibs = 1 : 1 : zipWith (+) fibs (tail fibs)

main = print (fibs !! 1000)

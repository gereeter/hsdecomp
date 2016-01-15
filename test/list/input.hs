{-# NOINLINE foo #-}
foo [] = "EmptyFoo"
foo (_:_) = "NonemptyFoo"

{-# NOINLINE bar #-}
bar [] = "EmptyBar"
bar (x:xs) = "NonemptyBar: " ++ xs

main = putStrLn (foo "TestFoo" ++ bar "TestBar")

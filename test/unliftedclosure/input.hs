main = print (eat 15 + eat 16)

eat n = go 1 where
    go x = if x < n then 1 + go (x + 1) else x

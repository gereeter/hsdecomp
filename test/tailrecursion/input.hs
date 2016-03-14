main = print (loop 5 + loop 6)

loop x = if x < 10 then loop (x + 1) else x

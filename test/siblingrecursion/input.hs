main = print (loop1 5 + loop1 6)

loop1 x = if x < 10 then loop2 (x + 1) else x
loop2 x = if x < 11 then loop1 (x + 1) else x

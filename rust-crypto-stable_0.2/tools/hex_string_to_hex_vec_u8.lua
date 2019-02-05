io.write("Enter your string: ")
local hex_string = io.read("*line")
local result_string = "["

for i = 1, string.len(hex_string), 2 do
    if i ~= 1 then result_string = result_string .. ", " end
    result_string = result_string .. "0x" .. string.sub(hex_string, i , i+1) 
end

result_string = result_string .. "]"

print("\n\n" .. result_string)


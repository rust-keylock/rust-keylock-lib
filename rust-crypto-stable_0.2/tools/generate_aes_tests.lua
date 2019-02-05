-- #settings

-- settings for http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
conf_mode_conversion = {"mode_of_operation", "blockcipher", "mode_of_action"}
conf_mode_of_operation = {ECB = "ECB", CTR = "CTR", CBC = "CBC"}
conf_mode_of_action = {Encrypt = "encrypt", Decrypt = nil}
conf_blockcipher = {["AES128"] = "AES128", ["AES192"] = "AES192", ["AES256"] = "AES256"}

conf_headings = {["Plaintext"] = "plaintext", ["Ciphertext"] = "ciphertext", ["Key"] = "key", ["IV"] = "iv", ["Init. Counter"] = "ctr"}


-- #lib

function string_trim(s)
	local n = s:find"%S"
	return n and s:match(".*%S", n) or ""
end
-- http://lua-users.org/lists/lua-l/2009-12/msg00904.html

-- #functions

function convert_mode(temp_mode)
	if type(temp_mode) ~= "table" then error("Error: non-table type given to 'convert_mode'!") end
	local mode = {}
	for k,v in pairs(conf_mode_conversion) do
		mode[v] = temp_mode[k]
	end
	if conf_mode_of_operation[mode["mode_of_operation"]] then
		mode["mode_of_operation"] = conf_mode_of_operation[mode["mode_of_operation"]]
	else
		return false
	end
	if conf_mode_of_action[mode["mode_of_action"]] then
		mode["mode_of_action"] = conf_mode_of_action[mode["mode_of_action"]]
	else
		return false
	end
	if conf_blockcipher[mode["blockcipher"]] then
		mode["blockcipher"] = conf_blockcipher[mode["blockcipher"]]
	else
		return false
	end
	return mode
end

function convert_test_vector(temp_test_vector)
	if type(temp_test_vector) ~= "table" then error("Error: non-table type given to 'convert_test_vector'!") end
	local test_vector = {}
	for k,v in pairs(temp_test_vector) do
		local heading = conf_headings[v[1]]
		if heading then
			if test_vector[heading] then
				test_vector[heading] = test_vector[heading] .. v[2]
			else
				test_vector[heading] = v[2]
			end
		end
	end
	return test_vector
end

function generate_hex_vector(hex_string)
	local result_string = "vec!["
	for i = 1, string.len(hex_string), 2 do
	    if i ~= 1 then result_string = result_string .. ", " end
	    result_string = result_string .. "0x" .. string.sub(hex_string, i , i+1) 
	end
	
	result_string = result_string .. "]"
	return result_string
end

function get_keysize(blockcipher)
	if blockcipher == "AES128" then
		return "aes::KeySize::KeySize128"
	elseif blockcipher == "AES192" then
		return "aes::KeySize::KeySize192"
	elseif blockcipher == "AES256" then
		return "aes::KeySize::KeySize256"
	else
		error("Error: get_keysize got an unknown blockcipher!")
	end
end

function create_rust_test(mode, test_vector, i)
	if not i then i = 1 end
	if mode.mode_of_action ~= "encrypt" then return false end
	local rust_str = "#[test]\nfn test_" .. string.lower(mode.blockcipher) .. "_" .. string.lower(mode.mode_of_operation)
	if mode.mode_of_operation == "ECB" or mode.mode_of_operation == "CBC" then
		-- code for blockmodes
		rust_str = rust_str  .. "_" .. mode.mode_of_action .. i .. "() {\n"
		rust_str = rust_str .. "\tlet key: Vec<u8> = " .. generate_hex_vector(test_vector.key) .. ";\n"
		if mode.mode_of_operation == "CBC" then
			rust_str = rust_str .. "\tlet iv: Vec<u8> = " .. generate_hex_vector(test_vector.iv) .. ";\n"
		end
		rust_str = rust_str .. "\t\n\tTestDataBlockMode {\n\t\tdata : " .. generate_hex_vector(test_vector.plaintext)
												  .. ",\n\t\texpected : " .. generate_hex_vector(test_vector.ciphertext)
												  .. ",\n\t\tencryptor : "
		if mode.mode_of_operation == "CBC" then
			rust_str = rust_str .. "new_encryptor_aessafe_cbc(" .. get_keysize(mode.blockcipher) .. ", &key[..], &iv[..]),\n\t\tdecryptor : new_decryptor_aessafe_cbc("
					.. get_keysize(mode.blockcipher) .. ", &key[..], &iv[..])"
		elseif mode.mode_of_operation == "ECB" then
			rust_str = rust_str .. "new_encryptor_aessafe_ecb(" .. get_keysize(mode.blockcipher) .. ", &key[..]),\n\t\tdecryptor : new_decryptor_aessafe_ecb("
					.. get_keysize(mode.blockcipher) .. ", &key[..])"
		end
		rust_str = rust_str .. "\n\t}.run_test()"
	elseif mode.mode_of_operation == "CTR" then
		-- code for streamciphers
		rust_str = rust_str .. i .. "() {\n"
		rust_str = rust_str .. "\tlet key: Vec<u8> = " .. generate_hex_vector(test_vector.key) .. ";\n"
		rust_str = rust_str .. "\tlet ctr: Vec<u8> = " .. generate_hex_vector(test_vector.ctr) .. ";\n"
		rust_str = rust_str .. "\t\n\tTestDataStreamMode {\n\t\tdata : " .. generate_hex_vector(test_vector.plaintext)
														  .. ",\n\t\texpected : " .. generate_hex_vector(test_vector.ciphertext)
														  .. ",\n\t\tstreamcipher_enc : aes::ctr(" .. get_keysize(mode.blockcipher) .. ", &key[..], &ctr[..])"
														  .. ",\n\t\tstreamcipher_dec : aes::ctr(" .. get_keysize(mode.blockcipher) .. ", &key[..], &ctr[..])\n\t}.run_test()"
	end
	rust_str = rust_str .. "\n}\n\n"
	string.gsub(rust_str, "\t", "    ")
	return rust_str
end


-- #main

io.write("Enter test data:\n")
local input_str = io.read("*all")
local result_str = ""
local temp_index = 1

while true do
	--find F.x.x
	temp_index = select(2, string.find(input_str, "F%.%d+%.%d+", temp_index))
	if temp_index then temp_index = temp_index + 1
	else break end
	local temp_mode = {}
	
	for i = temp_index, string.len(input_str) do
		local char = string.sub(input_str, i, i)
		if char == "\n" then
			table.insert(temp_mode, string_trim(string.sub(input_str, temp_index, i)))
			temp_index = i + 1
			break
		elseif char == "-" or char == "." then
			table.insert(temp_mode, string_trim(string.sub(input_str, temp_index, i - 1)))
			temp_index = i + 1
		end
	end
	
	local mode = convert_mode(temp_mode)
	if not mode then goto continue_loop end
	
	local read_heading = true
	local heading = ""
	local test_vector = {}
	
	for i = temp_index, string.len(input_str) do
		local char = string.sub(input_str, i, i)
		if read_heading then
			-- in read heading mode
			if string.match(char, "%s") and string.match(string.sub(input_str, i+1, i+1), "%s") then
				-- if we find 2 whitespace chars then we switch to reading value (and we save the heading)
				heading = string.sub(input_str, temp_index, i - 1)
				temp_index = i + 2
				read_heading = false
			end
		else
			-- in read value mode
			if string.match(char, "%u") then
				-- if we find an uppercase char we save the heading, value pair and switch to reading heading again
				local value = string.gsub(string.sub(input_str,temp_index, i - 1), "%s", "")
				table.insert(test_vector, {heading, value})
				if char == "F" then
					-- next test vector
					break
				end
				heading = ""
				temp_index = i
				read_heading = true
			end
		end
	end
	
	test_vector = convert_test_vector(test_vector)
	local rust_test = create_rust_test(mode, test_vector)
	if rust_test then
		result_str = result_str .. rust_test
	end
	::continue_loop::
end

print("\nRESULT\n======\n")
print(result_str)

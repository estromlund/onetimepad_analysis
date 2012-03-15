#ciphertext #1:
ct_1="315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e"

#ciphertext #2:
ct_2="234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f"

#ciphertext #3:
ct_3="32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb"

#ciphertext #4:
ct_4="32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa"

#ciphertext #5:
ct_5="3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070"

#ciphertext #6:
ct_6="32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4"

#ciphertext #7:
ct_7="32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce"

#ciphertext #8:
ct_8="315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3"

#ciphertext #9:
ct_9="271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027"

#ciphertext #10:
ct_10="466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83"

#target ciphertext (decrypt this one): 
ct_tar="32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
 
#ct_strs=[ct_1,ct_2,ct_3,ct_4,ct_5,ct_6,ct_7,ct_8,ct_9,ct_10]
$togDebug=false

def hex_str_to_char_arr(str)
  temp_arr=[]
  str.gsub(/([0-9a-zA-Z]{2})/) {|f| temp_arr<<f}
  return temp_arr
end

def combine_arrs(arr)
  all_arrs=[]
  arr.each do |a|
    all_arrs<<hex_str_to_char_arr(a)
  end
  return all_arrs
end

def xor_chars(char1,char2)
  (char1.ord.to_s(16).hex ^ char2.hex).to_s(16)
end

def xor_array_els_as_hex(a,b) #input two arrays each with hex characters as elements
  xoredarr=[]
  if a.length > b.length || a.length == b.length
    for i in 0..b.length-1
      xored = (a[i].hex ^ b[i].hex).to_s(16)
      xoredarr<<xored
    end
  else b.length > a.length
    for i in 0..a.length-1
      xored = (a[i].hex ^ b[i].hex).to_s(16)
      xoredarr<<xored
    end
  end
  return xoredarr
end

def hex_to_asc(hex_code) #hex code string (i.e. "20" for space) as input
  hex_code.hex.chr
end

def find_shifted_case(orig,final) #input arrays of same length and with ascii characters
  shifted_case=Array.new(orig.length,0)
  orig.each_with_index do |el, i|
    el=el.hex.chr
    fin=final[i].hex.chr
    if (el == fin.downcase) || (fin == el.downcase) #if original element matches upper or lowercase of final element in same position
      shifted_case[i]=1                             #mark as shift in case
    end
  end
  return shifted_case
end

def and_arrays(arr_coll) #takes collection of arrays as input, outputs AND of all those arrays
  max_len=0
  arr_coll.each do |el|      #find length of longest array in collection of arrays
    if el.length > max_len
      max_len = el.length
    end
  end
  result = arr_coll[0][0..(max_len-1)]
  arr_coll[1..arr_coll.length].each do |arr|
    arr[0..max_len-1].each_with_index do |el, ind|
      if el != result[ind]
        result[ind]=0
      end
    end
  end
  return result
end

def build_key_from_spaces(spaces_array, cts_array) #array of arrays showing spaces in cts
  key=[]
  spaces_array.each_with_index do |arr, arr_ind|
    arr.each_with_index do |el, el_ind|
      if el==1 #i.e. there is a space there
        #xor hex space (20) with the appropriate ct element --> that is the key value for that index (s ^ k ^ s = k)
        key[el_ind] = ("20".hex ^ cts_array[arr_ind][el_ind].hex).to_s(16)
      end
    end
  end
  return key
end

def decode(ct, key, debug=false) #given ciphertext array and key array, output plaintext as ascii string
  pt=[]
  ct.each_with_index do |el, ind|
  if ind>99
    sp="  "
  else
    sp=" "
  end
    if !key[ind].nil?
      pt << (el.hex ^ key[ind].hex).chr + sp
    else
      pt << "."+sp
    end
  end
  if debug
    pt=pt.join("|")
  else
    pt=pt.join("")
  end
end

def decode_cts(cts_array,key,debug)  #use decode method to do whole set of ciphertexts
  i=1
  cts_array.each do |arr|
    pt=decode(arr,key,debug)
    if debug
      j=0
      print "\n"
      print "ct #{i}: " 
      arr.length.times.each do |num|
        if num < 10 
          print "#{num} |" #add a space to preserve alignment with double digit stuff
        else
          print "#{num}|"
        end
      end
    print "\n" 
    end
    puts "ct #{i}: #{pt}" 
    i += 1 
  end
end

def set_key_val(ct_arr,ct_num, key, index, pt_value) #set specific key values
  if pt_value.length ==1
    key[index]=xor_chars(pt_value,ct_arr[ct_num-1][index])
  else #add a few letters in a row from a given starting point
    n=0
    pt_value.chars.each do |ltr|
      key[index+n]=xor_chars(ltr,ct_arr[ct_num-1][index+n])
      n=n+1
    end
  end
end

def main_key_build_run(ct_array, ct_tar_arr, debug=false)
  spaces_arrays=[]

#for one given ct......
  ct_array.each_with_index do |curr_ct_1,k|
    shifts_array_for_indiv_ct = []

#....xor one at a time with another ct --> result is m1^ m2 (but don't compare against self because xor would just be 0)
    ct_array.each_with_index.reject { |el,i| i == (ct_array.index(curr_ct_1)) }.each_with_index do |curr_ct_2,j|
      curr_ct_2=curr_ct_2[0]
      xor12 = xor_array_els_as_hex(curr_ct_1,curr_ct_2)

#Then xor m1^m2 with an array of spaces (hex 20)
      arr_spaces=Array.new(xor12.length,"20")
      xored_w_sp=xor_array_els_as_hex(xor12,arr_spaces) # --> m1^m2^s

#then compare m1^m2 and m1^m2^s to see if any hex values correspond to a shift in case
#if so, that means m1 is a space -- s^m2 would result in shift in case (a-->A) and then s^s^m2 would shift it back
      a=find_shifted_case(xor12,xored_w_sp)

#store that comparison between two cts
      shifts_array_for_indiv_ct << a
    end

#after comparing one ct against all others, if one position consistently shifted register when xored with space (hex 20) then
#it is most likely a space in that first ct --> we can find that by ANDing all arrays together
    spaces_in_ct=and_arrays(shifts_array_for_indiv_ct)

#store an array showing likely spaces for an invividual ct into a larger array that will hold individual arrays for each ct
    spaces_arrays<<spaces_in_ct

#do this all over again but with the next ct as the main comparison
  end

#after all cts have been analyzed, build the key using that data
#this is done by taking the array showing where spaces are in each plaintext, and where each space is, xor that ct (hex) value with
#the value for space (hex 20), and that is the key value for that character position, i.e. where m1=s (m1^k^s=s^k^s=k)
  key=build_key_from_spaces(spaces_arrays, ct_array)
  return key
end

def print_decoded_cts(key, ct_array, ct_tar_arr, debug=false)
  puts "key = #{key}"
  #try and decode target
  decoded_tar = decode(ct_tar_arr, key)
  puts "targ: #{decoded_tar}"
  decode_cts(ct_array,key,debug)
end

def pop_array(file)
  arr=[]
  File.open(file).each_line { |s| arr << s }
  arr
end

def process_inp(input, ct_arr, ct_tar_arr, key) #matches input (i.e. "1, cipher") to pt text in ct1, and fills in blanks
  ct_arr=[ct_tar_arr]+ct_arr

  ct_num, pos, txtval = input.split(/,[ ]*/)
  if ct_num.nil? || pos.nil? || txtval.nil?
    puts "improper input; should be ct_num,position,value"
  else
    if ct_num == ("tar" || "t")
      ct_num=0
    else
      ct_num=ct_num.to_i+1
    end
    set_key_val(ct_arr,ct_num, key, (pos.to_i-1), txtval)
  end
  
end


if __FILE__ == $0  #run this if executed from command line
    if ARGV.empty?
      puts %Q{\nProper usage is:\n\n '#{$0} cts_file'\n\nwhere cts_file is a file containing all ciphertexts, separated by a blank line}
      Process.exit
    end
    
    #load cts in file, each separated by blank line, with target as last line (actually doesn't matter bc all cts will be decrypted)
    ct_file = ARGV[0]
    ct_strs=File.open(ct_file).read.split("\n").reject { |el| el==""}
    
    #convert ct_strs to array of arrays containing each hex code (2 digits) in an array
    ct_array=combine_arrs(ct_strs)  # i.e. ["asdflk","asdkfjsaldj"]->[["as","df","lk"],["as",....]]
    ct_tar_arr=hex_str_to_char_arr(ct_tar) # same, but only one array 

    #do analysis, etc. up to and including building the key
    key=main_key_build_run(ct_array, ct_tar_arr)
    #then we enter loop where once can 

    # 1) toggle between debug and not
    # 2) add to the key using regex subs and maybe also by ct number
    # when those are added, or debug is toggled, everything is reprinted
   
    ct_arr=combine_arrs(ct_strs) 

    print_decoded_cts(key, ct_arr,ct_tar_arr,$togDebug)
    togDebug=false
    
    while true
      inp = $stdin.gets.chomp
      case inp
        when "D"
          if $togDebug
            $togDebug=false
            print_decoded_cts(key,ct_arr,ct_tar_arr,$togDebug)
          else
            $togDebug=true
            print_decoded_cts(key,ct_arr,ct_tar_arr,$togDebug)
          end
        when "Q"
          Process.exit
        else
          process_inp(inp, ct_arr, ct_tar_arr,key)
          print_decoded_cts(key,ct_arr,ct_tar_arr,$togDebug)
      end
    end


      # there is also and undo function
end

#Best computed guess before filling in blanks mentally:
#targ: T h e   s e c r e t   m e s s a g e   i s :   W h e . . . s . . .   a   s t r e a m   c i p h e r ,   n e . . . . . s e   t h e   k . y   m . r e . t h a n   . n . . 

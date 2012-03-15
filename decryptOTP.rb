$togDebug=false

#---Hex operations
def hex_str_to_char_arr(str)
  temp_arr=[]
  str.gsub(/([0-9a-zA-Z]{2})/) {|f| temp_arr<<f}
  return temp_arr
end

def hex_to_asc(hex_code) #hex code string (i.e. "20" for space) as input
  hex_code.hex.chr
end

#--Array operations
def combine_arrs(arr)
  all_arrs=[]
  arr.each do |a|
    all_arrs<<hex_str_to_char_arr(a)
  end
  return all_arrs
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

#Xor functions
def xor_hex(char1,char2)
  (char1.hex ^ char2.hex).to_s(16)
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

#Functions for analysis of ciphertexts
def find_shifted_case(orig,final) #input arrays of same length and with ascii characters
  shifted_case=Array.new(orig.length,0)
  orig.each_with_index do |el, i|
    el=hex_to_asc(el)
    fin=hex_to_asc(final[i])
    if (el == fin.downcase) || (fin == el.downcase) #if original element matches upper or lowercase of final element in same position
      shifted_case[i]=1                             #mark as shift in case
    end
  end
  return shifted_case
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
  if ind>98
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
      arr.length.times.reject {|el| el==0}.each do |num|
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
    key[index]=xor_hex(pt_value.ord.to_s(16),ct_arr[ct_num-1][index])
  else #add a few letters in a row from a given starting point
    n=0
    pt_value.chars.each do |ltr|
      key[index+n]=xor_hex(ltr.ord.to_s(16),ct_arr[ct_num-1][index+n])
      n=n+1
    end
  end
end

def main_key_build_run(ct_array, ct_tar_arr, debug=$togDebug)
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

def process_inp(input, ct_arr, ct_tar_arr, key) #matches input (i.e. "1,5, cipher") to fill text "cipher" starting at position 5 on ct# 1
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
    ct_inp=File.open(ct_file).read.split("\n").reject { |el| el==""}
    ct_strs=ct_inp[0..ct_inp.length-2]
    ct_tar=ct_inp[ct_inp.length-1]

    
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
    
    while true
      print_decoded_cts(key,ct_arr,ct_tar_arr,$togDebug)
      inp = $stdin.gets.chomp
      case inp
        when "D"
          if $togDebug
            $togDebug=false
          else
            $togDebug=true
          end
        when "Q"
          Process.exit
        else
          process_inp(inp, ct_arr, ct_tar_arr,key)
      end
    end


      # there is also and undo function
end

#Best computed guess before filling in blanks mentally:
#targ: T h e   s e c r e t   m e s s a g e   i s :   W h e . . . s . . .   a   s t r e a m   c i p h e r ,   n e . . . . . s e   t h e   k . y   m . r e . t h a n   . n . . 

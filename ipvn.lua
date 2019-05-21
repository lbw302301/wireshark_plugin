require "bit32"
do
	local function showAddress(buf, offset, source_length)
		local index = offset + 4
		local endIndex = offset + source_length - 1
		local toShow = ""
		for i = index, endIndex do
			local address = buf(i, 1):uint()
			if (address == 20) and (i ~= endIndex) then
				local nextAddress = buf(i+1,1):uint()
				if nextAddress>=31 then
					toShow = toShow..nextAddress.."."
					i = i + 1
				else
					toShow = toShow..address.."."
				end
			else
				toShow = toShow..address.."."
			end
		end
        return string.sub(toShow,0,#toShow-1)
	end
    --协议名称为FlexibleIP，在Packet Details窗格显示为Flexiable FlexibleIP
    local p_FlexibleIP = Proto("FlexibleIP","FlexibleIP")
    --协议的各个字段
    local n_version = ProtoField.uint8("FlexibleIP.version","version",base.HEX)
    --这里的base是显示的时候的进制
    local n_traffic_class = ProtoField.uint8("FlexibleIP.traffic_class", "traffic_class", base.HEX)
    local n_flow_label = ProtoField.uint16("FlexibleIP.flow_label", "flow_label", base.HEX)
	local n_payloadLength = ProtoField.uint16("FlexibleIP.payloadLength", "payloadLength", base.HEX)
	local n_hop_limit = ProtoField.uint8("FlexibleIP.hop_limit", "hop_limit", base.HEX)
	local n_source_address_tag = ProtoField.uint8("FlexibleIP.source_address_tag", "source_address_tag", base.HEX)
	local n_source_address = ProtoField.string("FlexibleIP.source_address", "source_address", base.NONE)
	local n_dest_address_tag = ProtoField.uint8("FlexibleIP.dest_address_tag", "dest_address_tag", base.HEX)
	local n_dest_address = ProtoField.bytes("FlexibleIP.dest_address", "dest_address", base.COLON)
	local n_protocol = ProtoField.uint8("FlexibleIP.protocol", "n_protocol", base.HEX)
	local n_data = ProtoField.bytes("FlexibleIP.ndata", "n_data", base.SPACE)
    --这里把FlexibleIP协议的全部字段都加到p_FlexibleIP这个变量的fields字段里
    p_FlexibleIP.fields = {n_version, n_traffic_class, n_flow_label, n_payloadLength, n_hop_limit, n_source_address_tag, n_source_address, n_dest_address_tag, n_dest_address, n_protocol,n_data}
    
    --这里是获取data这个解析器
    local data_dis = Dissector.get("data")
    
    local function ipn_dissector(buf,pkt,root)
		local buflen = buf:len()
		local offset = 0;
		--添加Packet Details
        local t = root:add(p_FlexibleIP,buf)
        --在Packet List窗格的Protocol列可以展示出协议的名称
        pkt.cols.protocol = "FlexibleIP"
        --这里是把对应的字段的值填写正确，只有t:add过的才会显示在Packet Details信息里. 所以在之前定义fields的时候要把所有可能出现的都写上
        --取出其他字段的值
		local v_version = buf(offset, 1)
		local temp_version = buf(offset ,1):uint()
		t:add(n_version, v_version, temp_version ,"version: "..string.format("%#x",temp_version).."(Flexible IP)")
		offset = offset+1
		
		if (bit32.band(0x08,temp_version)) then
			local v_traffic_class = buf(offset, 1)
			t:add(n_traffic_class, v_traffic_class)
			offset = offset + 1
		end
		
		if (bit32.band(0x04,temp_version)) then
			local v_flow_label = buf(offset, 2)
			t:add(n_flow_label, v_flow_label)
			offset = offset + 2
		end
		
		if (bit32.band(0x02,temp_version)) then
			local v_payloadLength = buf(offset, 2)
			t:add(n_payloadLength, v_payloadLength)
			offset = offset + 2
		end
		
		if (bit32.band(0x01,temp_version)) then
			local v_hop_limit = buf(offset, 1)
			t:add(n_hop_limit, v_hop_limit)
			offset = offset + 1
		end
		
		local v_source_address_tag = buf(offset, 1)
		local temp_source_address_tag = buf(offset, 1):uint()
		local source_length = bit32.band(0x1f, temp_source_address_tag)
		local source_address_tag_to_show = "source_address_tag: "..string.format("%#x",temp_source_address_tag).."(length: "..source_length..")"
		t:add(n_source_address_tag, v_source_address_tag, temp_source_address_tag, source_address_tag_to_show)
		offset = offset + 1
		
		local v_source_address = buf(offset, source_length)
		local temp_source_address = buf(offset, source_length):string()
        local source_address_toshow = "source_address: "..showAddress(buf,offset,source_length)
		t:add(n_source_address, v_source_address, temp_source_address, source_address_toshow)
		offset = offset + source_length
		
		local v_dest_address_tag = buf(offset, 1)
		local temp_dest_address_tag = buf(offset, 1):uint()
        local dest_length = bit32.band(0x1f,temp_dest_address_tag)
        local dest_address_tag_to_show = "dest_address_tag: "..string.format("%#x",temp_dest_address_tag).."(length: "..dest_length..")"
		t:add(n_dest_address_tag, v_dest_address_tag, temp_dest_address_tag, dest_address_tag_to_show)
		offset = offset + 1
		
		local v_dest_address = buf(offset, dest_length)
        local temp_dest_address = buf(offset, dest_length):string()
        local dest_address_toshow = "dest_address: "..showAddress(buf,offset,dest_length)
		t:add(n_dest_address, v_dest_address, temp_dest_address, dest_address_toshow)
		offset = offset + dest_length
		
		local v_protocol = buf(offset, 1)
		local temp_protocol = buf(offset, 1):uint()
		offset = offset + 1
		local v_data = buf(offset, (buflen - offset))
		local pro_toshow = "Protocol: "..temp_protocol
		if temp_protocol == 58 then
			Dissector.get("icmpv6"):call(v_data:tvb(), pkt, root)
			pro_toshow = pro_toshow.."(ICMPv6)"
		end
		if temp_protocol == 6 then 
			Dissector.get("tcp"):call(v_data:tvb(), pkt, root)
			pro_toshow = pro_toshow.."(TCP)"
		end
		if temp_protocol == 17 then
			Dissector.get("udp"):call(v_data:tvb(), pkt, root)
			pro_toshow = pro_toshow.."(UDP)"
		end
		if temp_protocol ~= 58 and temp_protocol ~= 6 and temp_protocol ~= 17 then
			t:add(n_data, v_data)
		end
		t:add(n_protocol,v_protocol,temp_protocol,pro_toshow)
		pkt.cols.protocol = "FlexibleIP"
		return true
    end
    
    --这段代码是目的Packet符合条件时，被Wireshark自动调用的，是p_FlexibleIP的成员方法
    function p_FlexibleIP.dissector(buf,pkt,root) 
        if ipn_dissector(buf,pkt,root) then
            --valid DT diagram
        else
            --data这个dissector几乎是必不可少的；当发现不是我的协议时，就应该调用data
            data_dis:call(buf,pkt,root)
        end
    end
    
    local ipn_encap_table = DissectorTable.get("ethertype")
    ipn_encap_table:add(0xffff, p_FlexibleIP)
end

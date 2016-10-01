require 'ffi/pcap'
require 'piface'

pcap = FFI::PCap::Live.new(dev: 'wlan0', timeout: 1, promisc: true, handler: FFI::PCap::Handler)
pcap.setfilter('arp')

puts "Listening..."  
pcap.loop do |this, pkt|
	macaddress = pkt.body.unpack("C*").
		map{|i| i.to_s(16) }.
		map{|i| if i.length == 1 then "0#{i}" else i end}.
		slice(6,6).
		join(":")
	if '0c:47:c9:4c:ad:d9' == macaddress
  		puts 'Pressed'
		Piface.write 0, 1
		puts 'On'
		sleep 4
		puts 'Off'
		Piface.write 0, 0
		puts 'Done'
	end
end

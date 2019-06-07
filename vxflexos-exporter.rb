require 'json'
require 'pry'
require 'net/http'
require 'openssl'
require 'socket'

app = VxFlexOSExporter.new
server = TCPServer.new @config['prom']['listen_port']

while session = server.accept
  app.get_auth_token
  app.get_tree
  app.get_stats
  app.process_stats

  request = session.gets
  puts request

  session.print "HTTP/1.1 200\r\n" # 1
  session.print "Content-Type: text/plaintext\r\n" # 2
  session.print "\r\n" # 3
  app.output_stats(session)

  session.close
  app.get_stats
  app.process_stats
end

class VxFlexOSExporter
  @config
  @query
  @defs
  @auth_token
  @tree
  @stats
  @stats_processed

  def initialize
    file = open("config.json") rescue raise('Config file config.json is missing in the root folder of Vxf2Prom')
    json = file.read
    @config = JSON.parse(json) rescue raise('Config file config.json has some syntax errors inside, please validate it')

    file = open("metric_query_selection.json") rescue raise('Config file metric_query_selection.json is missing in the root folder of Vxf2Prom')
    json = file.read
    @query = JSON.parse(json) rescue raise('Config file metric_query_selection.json has some syntax errors inside, please validate it')

    file = open("metric_definition.json") rescue raise('Config file metric_definition.json is missing in the root folder of Vxf2Prom')
    json = file.read
    @defs = JSON.parse(json) rescue raise('Config file metric_definition.json has some syntax errors inside, please validate it')
  end

  def get_auth_token
    uri = URI("https://#{@config['sio']['host']}:#{@config['sio']['port'] || 443}/api/login")

    Net::HTTP.start(@config['sio']['host'], @config['sio']['port'] || 443,
      :use_ssl => uri.scheme == 'https', 
      :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|

      request = Net::HTTP::Get.new(uri.request_uri)
      request.basic_auth(@config['sio']['user'], @config['sio']['pass'])

      response = http.request(request)

      if response.body.include?('Unauthorized')
        raise 'Auth at VXFlexOS failed: please check login and password in config.json'
      else
        @auth_token = response.body.gsub('"','')
      end
      puts 'Got auth token: ' + @auth_token
    end
  end

  def get_tree
    uri = URI("https://#{@config['sio']['host']}:#{@config['sio']['port'] || 443}/api/instances/")
    Net::HTTP.start(@config['sio']['host'], @config['sio']['port'] || 443,
      :use_ssl => uri.scheme == 'https', 
      :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|

      request = Net::HTTP::Get.new(uri.request_uri)
      request.basic_auth('', @auth_token)

      response = http.request(request)

      if response.body.include?('Unauthorized')
        raise 'Tree request failed: maybe the token expired?'
      else
        @tree = JSON.parse(response.body)
      end
    end
  end

  def get_stats
    uri = URI("https://#{@config['sio']['host']}:#{@config['sio']['port'] || 443}/api/instances/querySelectedStatistics")
    header = {'Content-Type': 'application/json'}
    
    Net::HTTP.start(@config['sio']['host'], @config['sio']['port'] || 443,
      :use_ssl => uri.scheme == 'https', 
      :verify_mode => OpenSSL::SSL::VERIFY_NONE) do |http|

        request = Net::HTTP::Post.new(uri.request_uri, header)
        request.basic_auth('', @auth_token)
        request.body = @query.to_json

        response = http.request(request)
        if response.body.include?('Unauthorized')
          puts 'Stats request failed: maybe the token expired?'
        else
          @stats = JSON.parse(response.body)
        end
    end
  end

  def process_stats
    @stats_processed = []
    @stats.each do |type, level1|
      tags = {clu_id: @tree['System']['id'], clu_name: @tree['System']['name']}
      if type != 'System'
        level1.each do |device_id, device_stats|
          if type == 'Sdc'
            tags.merge!({sdc_id: device_id, sdc_name: @tree['sdcList'].first{|sdc| sdc.id == device_id}['name']})
          elsif type == 'ProtectionDomain'
            tags.merge!({pdo_id: device_id, pdo_name: @tree['protectionDomainList'].first{|pdo| pdo.id == device_id}['name']})
          elsif type == 'Sds'
            protection_domain_id = @tree['sdsList'].first{|sds| sds.id == device_id}['protectionDomainId']
            tags.merge!({pdo_id: protection_domain_id, pdo_name: @tree['protectionDomainList'].first{|pdo| pdo.id == protection_domain_id}['name'], sds_id: device_id, sds_name: @tree['sdsList'].first{|sds| sds.id == device_id}['name']})
          elsif type == 'StoragePool'
            protection_domain_id = @tree['storagePoolList'].first{|sto| sto.id == device_id}['protectionDomainId']
            tags.merge!({pdo_id: protection_domain_id, pdo_name: @tree['protectionDomainList'].first{|pdo| pdo.id == protection_domain_id}['name'], sto_id: device_id, sto_name: @tree['storagePoolList'].first{|sto| sto.id == device_id}['name']})
          elsif type == 'Volume'
            storage_pool_id = @tree['volumeList'].first{|vol| vol.id == device_id}['storagePoolId']
            protection_domain_id = @tree['storagePoolList'].first{|sto| sto.id == storage_pool_id}['protectionDomainId']
            tags.merge!({pdo_id: protection_domain_id, pdo_name: @tree['protectionDomainList'].first{|pdo| pdo.id == protection_domain_id}['name'], sto_id: storage_pool_id, sto_name: @tree['storagePoolList'].first{|sto| sto.id == storage_pool_id}['name'], vol_id: device_id, vol_name: @tree['volumeList'].first{|vol| vol.id == device_id}['name']})
          elsif type == 'Device'
            storage_pool_id = @tree['deviceList'].first{|dev| dev.id == device_id}['storagePoolId']
            sds_id = @tree['deviceList'].first{|dev| dev.id == device_id}['sdsId']
            protection_domain_id = @tree['storagePoolList'].first{|sto| sto.id == storage_pool_id}['protectionDomainId']
            tags.merge!({pdo_id: protection_domain_id, pdo_name: @tree['protectionDomainList'].first{|pdo| pdo.id == protection_domain_id}['name'], sto_id: storage_pool_id, sto_name: @tree['storagePoolList'].first{|sto| sto.id == storage_pool_id}['name'], sds_id: sds_id, sds_name: @tree['sdsList'].first{|sds| sds.id == sds_id}['name'], dev_id: device_id, dev_name: @tree['deviceList'].first{|dev| dev.id == device_id}['name'], dev_path: @tree['deviceList'].first{|dev| dev.id == device_id}['deviceCurrentPathName']})
          end
          
          device_stats.each do |param, value|
            @stats_processed << {type: type, param: param, value: value, tags: tags}
          end
        end
      else
        level1.each do |param, value|
          @stats_processed << {type: type, param: param, value: value, tags: tags}
        end
      end
    end
  end

  def output_stats(target)
    @stats_processed.group_by{|s| s[:type]+s[:param]}.each do |group, rows|
      param_prom_name = rows[0][:param].gsub(/(.)([A-Z])/,'\1_\2').downcase
      if @defs[rows[0][:param]]
        target.print "# HELP #{rows[0][:param]} #{@defs[rows[0][:param]]['help']}" + "\r\n" if @defs[rows[0][:param]]['help']
        target.print "# TYPE #{rows[0][:param]} #{@defs[rows[0][:param]]['type']}" + "\r\n" if @defs[rows[0][:param]]['type']
        param_prom_name = @defs[rows[0][:param]]['name'] if @defs[rows[0][:param]]['name']
      end

      rows.each do |row|
        path_str = (@config['prom']['prefix'] || '') + row[:type].downcase + '_' + param_prom_name
        tags_str = '{' + row[:tags].map{|t,v| t.to_s + '="' + v + '"'}.join(', ') + '}'

        if row[:value].is_a?(Hash)
          target.print path_str + '_iops' + tags_str + ' ' + (row[:value]['numSeconds'] > 0 ? row[:value]['numOccured']/row[:value]['numSeconds'] : 0).to_s + "\r\n"
          target.print path_str + '_bw' + tags_str + ' ' + (row[:value]['numSeconds'] > 0 ? row[:value]['totalWeightInKb']/row[:value]['numSeconds'] : 0).to_s + "\r\n"
        else
          target.print path_str + tags_str + ' ' + row[:value].to_s + "\r\n"
        end
      end

    end
  end
end
#!/usr/bin/env ruby

require 'json'
require 'net/http'
require 'openssl'
require 'socket'

def gem_available?(name)
  Gem::Specification.find_by_name(name)
rescue Gem::LoadError
  false
end

require 'pry' if gem_available?('pry')

class VxFlexOSExporter
  PREFIX = 'vxf_'

  def initialize
    file = open("config.json") rescue raise('config file config.json is missing in the root folder of VxFlexOSExporter')
    json = file.read
    @config = JSON.parse(json) rescue raise('config file config.json has some syntax errors inside, please validate it')

    file = open("metric_query_selection.json") rescue raise('config file metric_query_selection.json is missing in the root folder of VxFlexOSExporter')
    json = file.read
    @query = JSON.parse(json) rescue raise('config file metric_query_selection.json has some syntax errors inside, please validate it')

    file = open("metric_definition.json") rescue raise('config file metric_definition.json is missing in the root folder of VxFlexOSExporter')
    json = file.read
    @defs = JSON.parse(json) rescue raise('config file metric_definition.json has some syntax errors inside, please validate it')

    if File.exists?('properties_selected.json')
      file = open("properties_selected.json")
      json = file.read
      @props = JSON.parse(json) rescue raise('config file properties_selected.json has some syntax errors inside, please validate it')
    end

    threads = []
    @config.each do |p_name, p_conf|
      threads << Thread.new(p_name, p_conf) do |profile_name, profile|
        puts "Starting VXFlexOS Exporter for #{profile_name} (#{profile['host']}) on port #{profile['listen_port']}"
        server = TCPServer.new(profile['listen_ip'] || '0.0.0.0', profile['listen_port'])

        while session = server.accept
          request = session.gets

          if request && (parts = request.split(' ')) && parts.size > 1
            begin
              puts "#{profile_name}: #{request}"
              if parts[1] == '/'
                session.print "HTTP/1.1 200\r\n"
                session.print "Content-Type: text/html\r\n"
                session.print "\r\n"
                session.print '<html>
                    <head><title>VXFlexOS Exporter</title></head>
                    <body>
                      <h1>VXFlexOS Exporter</h1>
                      <p><a href="/metrics">Metrics</a></p>
                    </body>
                  </html>'
              elsif parts[1] == '/metrics'
                begin
                  stats_processed = []

                  token = get_auth_token(host: profile['host'], port: (profile['port'] || 443), login: profile['user'], password: profile['pass'])
                  puts "#{profile_name}: got auth token #{token}"

                  tree = get_tree(host: profile['host'], port: (profile['port'] || 443), token: token)
                  version = tree['System']['systemVersionName'][/R\d/].gsub('R', 'v') #"DellEMC ScaleIO Version: R2_6.11000.113" / "DellEMC ScaleIO Version: R3_0.200.104"
                  raise("Version #{version} is not defined") if @query[version].nil?

                  stats_processed += process_tree(version: version, tree: tree)
                  storage_disk_ids = tree['deviceList'].select{|disk| !disk['storagePoolId'].nil?}.map{|disk| disk['id']}
                  acceleration_disk_ids = tree['deviceList'].select{|disk| !disk['accelerationPoolId'].nil?}.map{|disk| disk['id']}
                  stats = get_stats(version: version, host: profile['host'], port: (profile['port'] || 443), token: token, storage_disk_ids: storage_disk_ids, acceleration_disk_ids: acceleration_disk_ids)
                  stats_processed += process_stats(version: version, tree: tree, stats: stats)
                  stats_processed = convert_kb_iops(stats_processed)

                  session.print "HTTP/1.1 200\r\n"
                  session.print "Content-Type: text/plaintext\r\n"
                  session.print "\r\n"
                  output_stats(stats_processed, session)
                rescue => e
                  session.print "HTTP/1.1 500\r\n"
                  session.print "Content-Type: text/plaintext\r\n"
                  session.print "\r\n"
                  session.print "An exception raised while communicating with VXFlexOS: #{e}"
                end
              else
                session.print "HTTP/1.1 404\r\n"
                session.print "Content-Type: text/plaintext\r\n"
                session.print "\r\n"
                session.print "Not Found! VXFlexOS Exporter only listens on /metrics"
              end
            rescue => e
              puts "#{profile_name}: exception #{e}"
            end
          end

          session.close
        end
      end
    end 
    threads.each {|thr| thr.join }
  end

  def get_auth_token(params)
    uri = URI("https://#{params[:host]}:#{params[:port]}/api/login")

    Net::HTTP.start(params[:host], params[:port], use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      request = Net::HTTP::Get.new(uri.request_uri)
      request.basic_auth(params[:login], params[:password])

      response = http.request(request)
      json = JSON.parse(response.body) rescue nil
      if response.body.include?('Unauthorized')
        raise 'Auth at VXFlexOS failed: please check login and password in @config.json'
      else
        auth_token = response.body.gsub('"','')
      end
      return auth_token
    end
  end

  def get_tree(params)
    uri = URI("https://#{params[:host]}:#{params[:port]}/api/instances/")
    Net::HTTP.start(params[:host], params[:port], use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      request = Net::HTTP::Get.new(uri.request_uri)
      request.basic_auth('', params[:token])

      response = http.request(request)
      json = JSON.parse(response.body) rescue nil
      if !json
        raise(response.body)
      elsif [400,500].include?(json['httpStatusCode'])
        raise(json.to_s)
      else
        return JSON.parse(response.body)
        #File.open('examples/tree.json', 'w') { |file| file.write(JSON.pretty_generate(tree)) } if File.exists?('examples')
      end
    end
  end

  def process_tree(params)
    output = []
    @props[params[:version]].each do |type, properties|
      properties.each do |prop|
        if type != 'System'
          raise "Unexpected type #{type}, #{type[0, 1].downcase + type[1..-1] + 'List'} is missing in the Tree" if !params[:tree][type[0, 1].downcase + type[1..-1] + 'List']
          params[:tree][type[0, 1].downcase + type[1..-1] + 'List'].each do |value|
            id = value['id']
            prop['key'].split('/').each{|nextlevel| value = value[nextlevel]}
            output << {type: type,
                       param: prop['key'],
                       value: prop['values'] ? prop['values'][value.to_s] : value,
                       tags: get_tags(tree: params[:tree], type: type, id: id),
                       display_name: prop['name'] || prop['key'].gsub(/(.)([A-Z])/,'\1_\2').downcase,
                       help: prop['help'],
                       promtype: prop['type']
                      }
          end
        else
          value = params[:tree]['System']
          prop['key'].split('/').each{|nextlevel| value = value[nextlevel]}
          output << {type: type,
                     param: prop['key'],
                     value: prop['values'] ? prop['values'][value.to_s] : value,
                     tags: get_tags(tree: params[:tree], type: type),
                     display_name: prop['name'] || prop['key'].gsub(/(.)([A-Z])/,'\1_\2').downcase,
                     help: prop['help'],
                     promtype: prop['type']
                    }
        end
      end
    end
    output
  end

  def get_stats(params)
    uri = URI("https://#{params[:host]}:#{params[:port]}/api/instances/querySelectedStatistics")
    Net::HTTP.start(params[:host], params[:port], use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) do |http|
      request = Net::HTTP::Post.new(uri.request_uri, {'Content-Type': 'application/json'})
      request.basic_auth('', params[:token])
      query = @query[params[:version]].dup
      if params[:version] == 'v3'
        query['selectedStatisticsList'].select{|t| t['type'] == 'Device'}.first.delete('allIds')
        query['selectedStatisticsList'].select{|t| t['type'] == 'Device'}.first['ids'] = params[:storage_disk_ids]
      end
      request.body = query.to_json

      response = http.request(request)
      json = JSON.parse(response.body) rescue nil
      if !json
        raise(response.body)
      elsif [400,500].include?(json['httpStatusCode'])
        raise(json.to_s)
      else
        return json
        #File.open('examples/stats.json', 'w') { |file| file.write(JSON.pretty_generate(@stats)) } if File.exists?('examples')
      end
    end
  end

  def get_tags(params)
    tags = {sys_id: params[:tree]['System']['id'],
            sys_name: params[:tree]['System']['name']}
    if params[:type] == 'Sdc'
      sdc = params[:tree]['sdcList'].select{|sdc| sdc['id'] == params[:id]}.first
      tags.merge!({sdc_id: params[:id],
                   sdc_name: sdc['name']})
    elsif params[:type] == 'ProtectionDomain'
      protection_domain = params[:tree]['protectionDomainList'].select{|pdo| pdo['id'] == params[:id]}.first
      tags.merge!({pd_id: params[:id],
                   pd_name: protection_domain['name']})
    elsif params[:type] == 'Sds'
      protection_domain_id = params[:tree]['sdsList'].select{|sds| sds['id'] == params[:id]}.first['protectionDomainId']
      protection_domain = params[:tree]['protectionDomainList'].select{|pdo| pdo['id'] == protection_domain_id}.first
      sds = params[:tree]['sdsList'].select{|sds| sds['id'] == params[:id]}.first
      tags.merge!({pd_id: protection_domain_id,
                   pd_name: protection_domain['name'],
                   sds_id: params[:id],
                   sds_name: sds['name']})
    elsif params[:type] == 'StoragePool'
      protection_domain_id = params[:tree]['storagePoolList'].select{|sto| sto['id'] == params[:id]}.first['protectionDomainId']
      protection_domain = params[:tree]['protectionDomainList'].select{|pdo| pdo['id'] == protection_domain_id}.first
      storage_pool = params[:tree]['storagePoolList'].select{|sto| sto['id'] == params[:id]}.first
      tags.merge!({pd_id: protection_domain_id,
                   pd_name: protection_domain['name'],
                   stp_id: params[:id],
                   stp_name: storage_pool['name']})
    elsif params[:type] == 'AccelerationPool'
      protection_domain_id = params[:tree]['accelerationPoolList'].select{|acp| acp['id'] == params[:id]}.first['protectionDomainId']
      protection_domain = params[:tree]['protectionDomainList'].select{|pdo| pdo['id'] == protection_domain_id}.first
      acceleration_pool = params[:tree]['accelerationPoolList'].select{|acp| acp['id'] == params[:id]}.first
      tags.merge!({pd_id: protection_domain_id,
                   pd_name: protection_domain['name'],
                   acp_id: params[:id],
                   acp_name: acceleration_pool['name']})
    elsif params[:type] == 'Volume'
      storage_pool_id = params[:tree]['volumeList'].select{|vol| vol['id'] == params[:id]}.first['storagePoolId']
      storage_pool = params[:tree]['storagePoolList'].select{|sto| sto['id'] == storage_pool_id}.first
      protection_domain_id = storage_pool['protectionDomainId']
      protection_domain = params[:tree]['protectionDomainList'].select{|pdo| pdo['id'] == protection_domain_id}.first
      volume = params[:tree]['volumeList'].select{|vol| vol['id'] == params[:id]}.first
      tags.merge!({pd_id: protection_domain_id,
                   pd_name: protection_domain['name'],
                   stp_id: storage_pool_id,
                   stp_name: storage_pool['name'],
                   vol_id: params[:id],
                   vol_name: volume['name']})
    elsif params[:type] == 'Device' && (device = params[:tree]['deviceList'].select{|dev| dev['id'] == params[:id]}.first) && device['storagePoolId']
      storage_pool_id = device['storagePoolId']
      storage_pool = params[:tree]['storagePoolList'].select{|sto| sto['id'] == storage_pool_id}.first
      sds_id = device['sdsId']
      sds = params[:tree]['sdsList'].select{|sds| sds['id'] == sds_id}.first
      protection_domain_id = storage_pool['protectionDomainId']
      protection_domain = params[:tree]['protectionDomainList'].select{|pdo| pdo['id'] == protection_domain_id}.first
      tags.merge!({pd_id: protection_domain_id,
                   pd_name: protection_domain['name'],
                   stp_id: storage_pool_id,
                   stp_name: storage_pool['name'],
                   sds_id: sds_id,
                   sds_name: sds['name'],
                   dev_id: params[:id],
                   dev_name: device['name'],
                   dev_path: device['deviceCurrentPathName']})
    elsif params[:type] == 'Device' && (device = params[:tree]['deviceList'].select{|dev| dev['id'] == params[:id]}.first) && device['accelerationPoolId']
      acceleration_pool_id = device['accelerationPoolId']
      acceleration_pool = params[:tree]['accelerationPoolList'].select{|sto| sto['id'] == storage_pool_id}.first
      sds_id = device['sdsId']
      sds = params[:tree]['sdsList'].select{|sds| sds['id'] == sds_id}.first
      protection_domain_id = acceleration_pool['protectionDomainId']
      protection_domain = params[:tree]['protectionDomainList'].select{|pdo| pdo['id'] == protection_domain_id}.first
      tags.merge!({pd_id: protection_domain_id,
                    pd_name: protection_domain['name'],
                    acp_id: acceleration_pool_id,
                    acp_name: acceleration_pool['name'],
                    sds_id: sds_id,
                    sds_name: sds['name'],
                    dev_id: params[:id],
                    dev_name: device['name'],
                    dev_path: device['deviceCurrentPathName']})
    elsif params[:type] == 'RfcacheDevice'
      rfdevice = params[:tree]['rfcacheDeviceList'].select{|dev| dev['id'] == params[:id]}.first
      sds_id = rfdevice['sdsId']
      sds = params[:tree]['sdsList'].select{|sds| sds['id'] == sds_id}.first
      protection_domain_id = sds['protectionDomainId']
      protection_domain = params[:tree]['protectionDomainList'].select{|pdo| pdo['id'] == protection_domain_id}.first
      tags.merge!({pd_id: protection_domain_id,
                   pd_name: protection_domain['name'],
                   sds_id: sds_id,
                   sds_name: sds['name'],
                   rfdev_id: params[:id],
                   rfdev_name: rfdevice['name'],
                   rfdev_path: rfdevice['deviceCurrentPathname']})
    end
    tags
  end

  def process_stats(params)
    output = []
    params[:stats].each do |type, level1|
      if type != 'System'
        level1.each do |device_id, device_stats|
          device_stats.each do |param, value|
            if !@defs[param]
              puts "Warning: #{params[:version]} metric_definition lacks #{param} for #{type} - skipping"
            else
              output << {type: type, 
                        param: param,
                        value: value,
                        tags: get_tags(tree: params[:tree], type: type, id: device_id),
                        display_name: (@defs[param]['name'] ? @defs[param]['name'] : param.gsub(/(.)([A-Z])/,'\1_\2').downcase),
                        help: @defs[param]['help'],
                        promtype: @defs[param]['type']
                        }
            end
          end
        end
      else
        level1.each do |param, value|
          if !@defs[param]
            puts "Warning: #{params[:version]} metric_definition lacks #{param} for System - skipping"
          else
            output << {type: type,
                        param: param,
                        value: value,
                        tags: get_tags(tree: params[:tree], type: type),
                        display_name: (@defs[param]['name'] || param.gsub(/(.)([A-Z])/,'\1_\2').downcase),
                        help: @defs[param]['help'],
                        promtype: @defs[param]['type']
                      }
          end
        end
      end
    end
    output
  end

  def convert_kb_iops(target)
    conv = []
    target.each do |row|
      if row[:value].is_a?(Hash)
        conv << {type: row[:type],
                 param: row[:param],
                 postfix: 'iops',
                 value: (row[:value]['numSeconds'] > 0 ? row[:value]['numOccured']/row[:value]['numSeconds'] : 0),
                 tags: row[:tags],
                 display_name: row[:display_name],
                 help: row[:help],
                 promtype: row[:promtype]
                }
        conv << {type: row[:type],
                 param: row[:param],
                 postfix: 'kb',
                 value: (row[:value]['numSeconds'] > 0 ? row[:value]['totalWeightInKb']/row[:value]['numSeconds'] : 0),
                 tags: row[:tags],
                 display_name: row[:display_name],
                 help: row[:help],
                 promtype: row[:promtype]
                }
      else
        conv << row
      end
    end
    conv
  end

  def output_stats(stats, target)
    stats.group_by{|s| s[:type]+s[:param]+(s[:postfix] || '')}.each do |group, rows|
      path_str = PREFIX + rows[0][:type].downcase + '_' + rows[0][:display_name] + (rows[0][:postfix] ? '_'+rows[0][:postfix] : '')
      target.print "# HELP #{path_str} #{rows[0][:help]}" + "\n" if rows[0][:help]
      target.print "# TYPE #{path_str} #{rows[0][:promtype]}" + "\n" if rows[0][:promtype]

      rows.each do |row|
        tags_str = '{' + row[:tags].map{|t,v| t.to_s + '="' + v + '"'}.join(',') + '}'
        target.print path_str + tags_str + ' ' + row[:value].to_s + "\n"
      end
    end
  end
end

app = VxFlexOSExporter.new
package com.viettel;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.Buffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.viettel.model.Event;

public class Main {
    public static String RULE = "package com.viettel;\r\n" + //
            "import com.viettel.model.Event;\r\n" + //
            "import com.viettel.model.AlertEvent;\r\n";

    public static Event createEventByJson(String json) throws JsonProcessingException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        Event event = mapper.reader(Event.class).readValue(json);
        Map<String, String> unknownFields = mapper.readValue(json, HashMap.class);
        event.setUnknownFields(unknownFields);
        return event;
    }

    public static int fuzzing(String test_case, String filter) throws JsonParseException, JsonMappingException, IOException{
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> jsonMap = mapper.readValue(test_case, HashMap.class);
        List<Event> events = new ArrayList<>();
        for(String key : jsonMap.keySet()){
            Object value = jsonMap.get(key);
            jsonMap.put(key, null);
	        String temp_json = (new Gson()).toJson(jsonMap);
            events.add(createEventByJson(temp_json));
            jsonMap.put(key, value);
        }
        Correlation correlation = new Correlation(RULE+filter);
        try{
             correlation.fuzzing(events);
        }
        catch(Exception e){
            return -1;
        }
        
        return 1;
    }

    public static int testRule(String test_case, String filter) throws JsonProcessingException, IOException {
        Event event = createEventByJson(test_case);
        Correlation filterCorrelation = new Correlation(RULE + filter);
        try {
            filterCorrelation.test(event);
            // System.out.println(event.getFiltered_ids());
        } catch (Exception e) {
            // TODO: handle exception
            // e.printStackTrace();
            return -1;
        }
        System.out.println(event.getFiltered_ids());
        return event.getFiltered_ids().size();
    }

    public static String readFile(String fileName) throws IOException{
        FileReader file = new FileReader(fileName, Charset.forName("UTF-8"));
        BufferedReader br = new BufferedReader(file);
        String line;
        String out = "";
        while((line = br.readLine()) != null){
            out += line + "\n";
        }
        br.close();
        return out;
    }

    public static void main(String[] args){
        // arguments parse
        Map<String, String> parser = new HashMap<>();
        for (int index = 0; index < args.length; index++) {
            if (!args[index].startsWith("-"))
                continue;
            parser.put(args[index], args[index + 1]);
        }

        // get input
        String test_case = "";
        String filter = "";

        try {
            test_case = readFile(parser.get("-r"));
            filter = readFile(parser.get("-f"));
            if(parser.get("--fuzzing").equals("true")){
                System.out.println(fuzzing(test_case, filter));  
            }
            else
                System.out.println(testRule(test_case, filter));  
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(-1);
        }
    }
}

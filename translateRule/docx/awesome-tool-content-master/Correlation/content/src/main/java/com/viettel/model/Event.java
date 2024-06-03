package com.viettel.model;

import java.util.ArrayList;
import java.util.List;

public class Event extends EventBase{
    List<String> filtered_ids;
    Integer severity;

    public Event() {
        this.filtered_ids = new ArrayList<>();
    }

    public List<String> getFiltered_ids() {
        return filtered_ids;
    }

    public void addFilteredId(String filtered_id){
        this.filtered_ids.add(filtered_id);
    }

    public Integer getSeverity() {
        return severity;
    }

    public void setSeverity(Integer severity) {
        this.severity = severity;
    }
}

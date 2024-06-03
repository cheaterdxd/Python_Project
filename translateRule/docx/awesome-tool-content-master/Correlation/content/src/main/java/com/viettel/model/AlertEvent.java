package com.viettel.model;

public class AlertEvent extends Event{
    String rule_id;
    String description;
    String description_en;
    Integer release_level;

    public String getRule_id() {
        return rule_id;
    }

    public void setRule_id(String rule_id) {
        this.rule_id = rule_id;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDescription_en() {
        return description_en;
    }

    public void setDescription_en(String description_en) {
        this.description_en = description_en;
    }

    public Integer getRelease_level() {
        return release_level;
    }

    public void setRelease_level(Integer release_level) {
        this.release_level = release_level;
    }
    
}

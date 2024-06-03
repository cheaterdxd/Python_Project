package com.viettel;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import org.kie.api.KieBase;
import org.kie.api.KieServices;
import org.kie.api.builder.KieBuilder;
import org.kie.api.builder.KieFileSystem;
import org.kie.api.builder.Message;
import org.kie.api.builder.ReleaseId;
import org.kie.api.builder.Results;
import org.kie.api.runtime.KieContainer;
import org.kie.api.runtime.KieSession;

import com.viettel.model.AlertEvent;
import com.viettel.model.Event;

public class Correlation {
    private final String rule;
    private final KieSession session;

    public Correlation(String ruleFile){
        this.rule = ruleFile;
        this.session = createKieSession();
    }

    public void test(Event event){
        session.insert(event);
        session.fireAllRules();
    }

    public void fuzzing(List<Event> events){
        for(Event event: events){
            session.insert(event);
        }
        session.fireAllRules();
    }

    private KieSession createKieSession() {
        // Programmatically collect resources and build a KieContainer
        KieServices kieServices = KieServices.Factory.get();
        KieFileSystem kfs = kieServices.newKieFileSystem();
        kfs.write("src/main/resources/simple.drl",
                kieServices.getResources().newReaderResource(new StringReader(rule)));
        KieBuilder kieBuilder = kieServices.newKieBuilder(kfs).buildAll();

        //check there have been no errors for rule setup
        Results results = kieBuilder.getResults();
        if (results.hasMessages(Message.Level.ERROR)) {
        System.out.println(results.getMessages());
        throw new IllegalStateException("### errors ###");
        }
        KieContainer kieContainer =
        kieServices.newKieContainer(kieBuilder.getKieModule().getReleaseId());
        KieSession kieSession = kieContainer.newKieSession();
        return kieSession;
    }
}

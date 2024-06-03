package com.viettel.model;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;

import org.kie.api.runtime.rule.AccumulateFunction;

public class IndicatorEvent extends Event implements AccumulateFunction{

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'writeExternal'");
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'readExternal'");
    }

    @Override
    public Serializable createContext() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'createContext'");
    }

    @Override
    public void init(Serializable context) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'init'");
    }

    @Override
    public void accumulate(Serializable context, Object value) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'accumulate'");
    }

    @Override
    public void reverse(Serializable context, Object value) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'reverse'");
    }

    @Override
    public Object getResult(Serializable context) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getResult'");
    }

    @Override
    public boolean supportsReverse() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'supportsReverse'");
    }

    @Override
    public Class getResultType() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getResultType'");
    }

    @Override
    public String toString() {
        return "IndicatorEvent []";
    }
    
}

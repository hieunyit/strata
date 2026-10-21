import {render,screen} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import '../i18n';
import {HealthPage,healthState} from '../pages/HealthPage';
import {StaticAuthProvider} from '../context/AuthContext';
import {apiClient,HealthCheck} from '../api/client';
const check:HealthCheck={id:'fail_open',state:'healthy',observed_at:new Date().toISOString(),value:'0',advice:'fail_open'};
describe('health freshness',()=>{
 it('ages cached observations even if polling stalls',()=>{
 const at=new Date().toISOString(),now=Date.parse(at);
 expect(healthState(check,at,90,now,false)).toBe('healthy');
 expect(healthState(check,at,90,now+91000,false)).toBe('stale');
 expect(healthState({...check,state:'degraded'},at,90,now+91000,false)).toBe('stale');
 expect(healthState(check,at,90,now,true)).toBe('unavailable');
 expect(healthState(check,new Date(now+60000).toISOString(),90,now,false)).toBe('stale');
 });
 it('shows unknown sources and measured zero as distinct states',async()=>{
 vi.spyOn(apiClient,'systemHealth').mockResolvedValue({at:new Date().toISOString(),fresh_for_seconds:90,version:'dev',scope:'global',checks:[{id:'postgres',state:'unknown',observed_at:null,advice:'postgres'},check],nodes:[],truncated:false});
 render(<StaticAuthProvider roles={['viewer']}><HealthPage/></StaticAuthProvider>);
 expect(await screen.findByTestId('health-postgres')).toHaveAttribute('data-state','unknown');
 expect(screen.getByTestId('health-fail_open')).toHaveAttribute('data-state','healthy');
 expect(screen.getByTestId('health-fail_open')).toHaveTextContent('0');
 });
});

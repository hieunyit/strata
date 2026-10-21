import {beforeEach,expect,it,vi} from 'vitest';
import {fireEvent,render,screen} from '@testing-library/react';
import {apiClient,OperationalIncidentPage,ReportScheduleReply} from '../api/client';
import {StaticAuthProvider} from '../context/AuthContext';
import {OperationsPage} from '../pages/OperationsPage';
import i18n from '../i18n';
const incident:OperationalIncidentPage={editable:true,limit:200,incidents:[{id:'incident-a',application_id:'example-api',environment_id:'test',kind:'heartbeat',state:'open',signal_state:'degraded',affected:3,etag:'incident-etag',opened_at:'2026-10-21T00:00:00Z',observed_at:'2026-10-21T00:00:00Z',notified_at:null,ack_subject:''}]};
const schedule:ReportScheduleReply={schedule:null,scope_changed:false,editable:true};
beforeEach(()=>{vi.restoreAllMocks();void i18n.changeLanguage('en');vi.spyOn(apiClient,'getVersion').mockResolvedValue({version:'test'});vi.spyOn(apiClient,'listApplications').mockResolvedValue({applications:[{id:'example-api',name:'Example',owner:'operator',etag:'app-etag',created_at:'2026-10-21T00:00:00Z',updated_at:'2026-10-21T00:00:00Z',environments:[{id:'test',name:'Test',group_id:'example-group'}],routes:[]}],next_cursor:''});vi.spyOn(apiClient,'incidents').mockResolvedValue(incident);vi.spyOn(apiClient,'reportSchedule').mockResolvedValue(schedule);vi.spyOn(apiClient,'applicationReports').mockResolvedValue([]);});
async function scope(){await screen.findByRole('option',{name:'Example'});fireEvent.change(screen.getByRole('combobox',{name:'Application'}),{target:{value:'example-api'}});fireEvent.change(screen.getByRole('combobox',{name:'Environment'}),{target:{value:'test'}});}
it('uses the server authority for acknowledgment and schedule writes',async()=>{
 vi.mocked(apiClient.incidents).mockResolvedValue({...incident,editable:false});vi.mocked(apiClient.reportSchedule).mockResolvedValue({...schedule,editable:false});
 render(<StaticAuthProvider roles={['viewer']}><OperationsPage/></StaticAuthProvider>);await scope();await screen.findByText('3');expect(screen.queryByRole('button',{name:'Acknowledge'})).not.toBeInTheDocument();expect(screen.queryByRole('button',{name:'Save'})).not.toBeInTheDocument();expect(screen.getByRole('checkbox',{name:'Enable scheduled reports'})).toBeDisabled();
});
it('retries the same durable schedule command after a lost response',async()=>{
 const save=vi.spyOn(apiClient,'saveReportSchedule').mockRejectedValueOnce(new Error('reply lost')).mockResolvedValue(schedule);
 render(<StaticAuthProvider roles={['operator']}><OperationsPage/></StaticAuthProvider>);await scope();fireEvent.click(await screen.findByRole('checkbox',{name:'Enable scheduled reports'}));fireEvent.click(screen.getByRole('button',{name:'Save'}));await screen.findByRole('alert');fireEvent.click(screen.getByRole('button',{name:'Save'}));await screen.findByText('Schedule saved.');expect(save.mock.calls[0]).toEqual(save.mock.calls[1]);expect(save.mock.calls[0][0].schedule.enabled).toBe(true);
});
it('acknowledges the observed etag',async()=>{
 const ack=vi.spyOn(apiClient,'acknowledgeIncident').mockResolvedValue({...incident.incidents[0],state:'acknowledged'});
 render(<StaticAuthProvider roles={['operator']}><OperationsPage/></StaticAuthProvider>);await scope();fireEvent.click(await screen.findByRole('button',{name:'Acknowledge'}));expect(ack).toHaveBeenCalledWith(expect.objectContaining({id:'incident-a',etag:'incident-etag',application_id:'example-api',environment_id:'test'}));
});
